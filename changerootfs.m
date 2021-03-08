#include <stdio.h>
#import <Foundation/Foundation.h>

#include "config.h"
#include "kernel.h"
#include "vnode_utils.h"

#include <dirent.h>

#include "kcall.h"
#include "libkrw.h"

//#if 0
extern CFNotificationCenterRef CFNotificationCenterGetDistributedCenter(void);

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

    kern_return_t ret;
    kcall(&ret, f, 3, dict, ks, val);

    kdealloc(ks, len);

    return ret;
}

uint64_t OSDictionary_GetItem(uint64_t dict, const char *key) {
    size_t len = strlen(key) + 1;

    uint64_t ks = 0;
    kmalloc(&ks, len);
    kwrite_buf_univ(ks, key, len);

    uint64_t vtab = kernel_read64(dict);
    uint64_t f = kernel_read64(vtab + off_OSDictionary_GetObjectWithCharP);
    printf("f: 0x%llx, ks: 0x%llx\n", f - kslide, ks);

    kern_return_t ret;
    printf("wait for kcall 3sec.. should be panic\n");
    sleep(3);
    kcall(&ret, f, 2, dict, ks);
    
    kdealloc(ks, len);

    return ret;
}

uint64_t OSUnserializeXML(const char* buffer) {
    size_t len = strlen(buffer) + 1;

    uint64_t ks = 0;
    kmalloc(&ks, len);
    kwrite_buf_univ(ks, buffer, len);

    uint64_t errorptr = 0;

    kern_return_t ret;
    kcall(&ret, 0xFFFFFFF00765A3F4 + kslide/*find_osunserializexml()*/, 2/*size_t argc*/, ks, errorptr);

    kdealloc(ks, len);

    return ret;
}

uint64_t get_iucc_osarray(void) {
    return OSUnserializeXML("<array>"
    "<string>IOSurfaceAcceleratorClient</string>"
    "<string>IOMobileFramebufferUserClient</string>"
    "<string>IOSurfaceRootUserClient</string>"
    "</array>");
}

bool change_rootvnode(uint64_t vp, pid_t pid){
    
    if(!vp) return false;
    
    printf("getting proc_t\n");
    uint64_t proc = proc_of_pid(pid);
    
    if(!proc) return false;
    
    printf("escape sandbox\n");
    uint64_t creds = kernel_read64(proc + off_p_ucred/*0xf0*/);
    uint64_t cr_label = kernel_read64(creds + off_ucred_cr_label/*0x78*/);
    kernel_write64(cr_label + off_sandbox_slot/*0x10*/, 0);
    
    uint64_t amfi_entitlements = kernel_read64(cr_label + off_amfi_slot);
    printf("amfi_entitlements: 0x%llx\n", amfi_entitlements);
    
    kcall_init();
    
    if(OSDictionary_GetItem(amfi_entitlements, "get-task-allow") == 0) {
        printf("seems like get-task-allow not exist..\n");
    } else {
        printf("seems like get-task-allow EXIST!\n");
    }
    
    
    printf("get_iucc_osarray: 0x%llx\n", get_iucc_osarray());
    
//    OSDictionary_SetItem(amfi_entitlements, "get-task-allow", 0xFFFFFFF0076302E8 + kslide /*offset_osboolean_true*/);
    
    kcall_term();
    
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
    
    if(kcall_init() != KERN_SUCCESS) {
        printf("error kcall_init\n");
        return 1;
    }
    
    kern_return_t ret;
    if(kcall(&ret, (0xFFFFFFF0075038B0 + kslide)/*csblob_get_cdhash*/, 1, 0x48/*user_client_trap_off*/) == KERN_SUCCESS) {
        printf("testing kcall... csblob_get_cdhash(USER_CLIENT_TRAP_OFF): 0x%" PRIX32 "\n", ret);
    }
    
    kcall_term();
    
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
