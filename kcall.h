#include <mach/mach.h>
#include "libdimentio.h"
#include <IOKit/IOTypes.h>

typedef uint64_t kaddr_t;
typedef uint32_t ipc_entry_num_t;
typedef struct {
    kaddr_t obj, func, delta;
} io_external_trap_t;

kern_return_t
IOServiceClose(io_connect_t);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

CFMutableDictionaryRef
IOServiceMatching(const char *);

kern_return_t
IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);

kern_return_t
IOObjectRelease(io_object_t);

kern_return_t
mach_vm_copy(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t);

kern_return_t
IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);


extern const mach_port_t kIOMasterPortDefault;
void kcall_term(void);
kern_return_t kcall_init(void);
kern_return_t kcall(kern_return_t *ret, kaddr_t func, size_t argc, ...);
