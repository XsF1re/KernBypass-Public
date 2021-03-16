#import "sandbox.h"
#include "kernel.h"
#include "kcall.h"
#include "libkrw.h"
#include "config.h"

// defines
#define EXT_TABLE_SIZE 9
#define RET_ERR 0xC
#define RET_OK  0x0

// structures
struct extension_hdr {
    extension_hdr_t next;
    extension_t ext_lst;
    char desc[];
};

struct extension {
    extension_t next;           // 0: 0x0000000000000000;
    uint64_t desc;              // 8: 0xffffffffffffffff;
    uint8_t something[20];      // 16: all zero
    uint16_t num;               // 36: 1
    uint8_t type;               // 38: -
    uint8_t num3;               // 39: 0
    uint32_t subtype;           // 40: -
    uint32_t num4;              // 44: -
    void* data;                 // 48: -
    uint64_t data_len;          // 56: -
    uint16_t num5;              // 64: 0 for files
    uint8_t something_2[14];    // 66: -
    uint64_t ptr3;              // 80: 0 for files
    uint64_t ptr4;              // 88: -
    // 96: END OF STRUCT
};

// kernel_utils.m
int Kernel_strcmp(uint64_t kstr, const char* str) {
    // XXX be safer, dont just assume you wont cause any
    // page faults by this
    size_t len = strlen(str) + 1;
    char *local = malloc(len + 1);
    local[len] = '\0';
    
    int ret = 1;
    
    if (kread_buf_univ(kstr, local, len) == len) {
        ret = strcmp(local, str);
    }
    
    free(local);
    
    return ret;
}

// utils
uint64_t smalloc(uint64_t size) {
    kern_return_t ret;
    kcall(&ret, 0xFFFFFFF0069B9D78 + kslide, 1, size);
    printf("smalloc ret: 0x%x, size: 0x%llx\n", ret, size);
    return ret;
//    uint64_t ret = Kernel_Execute(Find_smalloc(), size, 0, 0, 0, 0, 0, 0);
//    return (ret) ? ZmFixAddr(ret) : ret;
}

uint64_t sstrdup(const char* s) {
    size_t slen = strlen(s) + 1;
    
    uint64_t ks = smalloc(slen);
    if (ks) {
        kwrite_buf_univ(ks, s, slen);
    }
    
    return ks;
}

unsigned int hashingMagic(const char *desc) {
    //size_t keyLen = strlen(desc);
    unsigned int hashed;
    char ch, ch2;
    char *chp;
    
    ch = *desc;
    
    if (*desc) {
        chp = (char *)(desc + 1);
        hashed = 0x1505;
        
        do {
            hashed = 33 * hashed + ch;
            ch2 = *chp++;
            ch = ch2;
        }
        while (ch2);
    }
    else hashed = 0x1505;
    
    return hashed % 9;
}

// actual sandbox stuff
uint64_t createFileExtension(const char* path, uint64_t nextptr) {
    size_t slen = strlen(path);
    
    if (path[slen - 1] == '/') {
        printf("[-] No traling slash in path pls\n");
        return 0;
    }
    
    uint64_t ext_p = smalloc(sizeof(struct extension));
    
    
    size_t len = strlen(path) + 1;
    uint64_t ks = 0;
    kmalloc(&ks, len);
    kwrite_buf_univ(ks, path, len);
//    uint64_t ks = sstrdup(path);
    
    if (ext_p && ks) {
        struct extension ext;
        bzero(&ext, sizeof(ext));
        ext.next = (extension_t)nextptr;
        ext.desc = 0xffffffffffffffff;
        
        ext.type = ET_FILE;
        ext.subtype = 0;
        
        ext.data = (void*)ks;
        ext.data_len = slen;
        
        ext.num = 1;
        ext.num3 = 1;
        
        kwrite_buf_univ(ext_p, &ext, sizeof(ext));
    } else {
        printf("ext_p: 0x%llx, ks: 0x%llx\n", ext_p, ks);
        printf("[-] Failed to create sandbox extension\n");
        exit(0);
    }
    
    return ext_p;
}

uint64_t make_ext_hdr(const char* key, uint64_t ext_lst) {
    struct extension_hdr hdr;
    
    uint64_t khdr = smalloc(sizeof(hdr) + strlen(key) + 1);
    
    if (khdr) {
        // we add headers to end
        hdr.next = 0;
        hdr.ext_lst = (extension_t)ext_lst;
        
        kwrite_buf_univ(khdr, &hdr, sizeof(hdr));
        kwrite_buf_univ(khdr + offsetof(struct extension_hdr, desc), key, strlen(key) + 1);
    }
    
    return khdr;
}

void extension_add(uint64_t ext, uint64_t sb, const char* ent_key) {
    // XXX patchfinder + kexecute would be way better
    
    int slot = hashingMagic(ent_key);
    uint64_t ext_table = kernel_read64(sb + 8);
    uint64_t insert_at_p = ext_table + slot * 8;
    uint64_t insert_at = kernel_read64(insert_at_p);
    
    printf("slot: %d, ext_table: 0x%llx, insert_at_p: 0x%llx, insert_at: 0x%llx\n", slot, ext_table, insert_at_p, insert_at);

    
    while (insert_at != 0) {
        uint64_t kdsc = insert_at + offsetof(struct extension_hdr, desc);
        printf("kdsc: 0x%llx\n", kdsc - kslide);

        if (Kernel_strcmp(kdsc, ent_key) == 0) {
            break;
        }
        
        insert_at_p = insert_at;
        insert_at = kernel_read64(insert_at);
        printf("insert_at_p: 0x%llx\n", insert_at_p);
        printf("insert_at: 0x%llx\n", insert_at);
    }
    
    if (insert_at == 0) {
        insert_at = make_ext_hdr(ent_key, ext);
        kernel_write64(insert_at_p, insert_at);
    } else {
        // XXX no duplicate check
        uint64_t ext_lst_p = insert_at + offsetof(struct extension_hdr, ext_lst);
        uint64_t ext_lst = kernel_read64(ext_lst_p);
        
        while (ext_lst != 0) {
            printf("[-] ext_lst_p = 0x%llx ext_lst = 0x%llx\n", ext_lst_p, ext_lst);
            ext_lst_p = ext_lst + offsetof(struct extension, next);
            ext_lst = kernel_read64(ext_lst_p);
        }
        
        printf("[-] ext_lst_p = 0x%llx ext_lst = 0x%llx\n", ext_lst_p, ext_lst);
        
        kernel_write64(ext_lst_p, ext);
    }
}

bool hasFileExtension(uint64_t sb, const char* path, char *ent_key) {
    const char* desc = ent_key;
    bool found = 0;
    
    int slot = hashingMagic(ent_key);
    uint64_t ext_table = kernel_read64(sb + 8);
    uint64_t insert_at_p = ext_table + slot * 8;
    uint64_t insert_at = kernel_read64(insert_at_p);
    
    while (insert_at != 0) {
        uint64_t kdsc = insert_at + offsetof(struct extension_hdr, desc);
        
        if (Kernel_strcmp(kdsc, desc) == 0) {
            break;
        }
        
        insert_at_p = insert_at;
        insert_at = kernel_read64(insert_at);
    }
    
    if (insert_at != 0) {
        uint64_t ext_lst = kernel_read64(insert_at + offsetof(struct extension_hdr, ext_lst));
        
        uint64_t plen = strlen(path);
        char *exist = malloc(plen + 1);
        exist[plen] = '\0';
        
        while (ext_lst != 0) {
            
            uint64_t data_len = kernel_read64(ext_lst + offsetof(struct extension, data_len));
            if (data_len == plen) {
                uint64_t data = kernel_read64(ext_lst + offsetof(struct extension, data));
                kread_buf_univ(data, exist, plen);
                
                if (!strcmp(path, exist)) {
                    found = 1;
                    break;
                }
            }
            ext_lst = kernel_read64(ext_lst);
        }
        free(exist);
    }
    
    return found;
}

bool addSandboxExceptionsToPid(pid_t pid, char *ent_key, char **paths) {
    uint64_t proc = proc_of_pid(pid);
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    uint64_t sandbox = kernel_read64(cr_label + off_sandbox_slot);
    
    if (!sandbox) {
        printf("[sbex][i] Pid %d is not sandboxed!\n", pid);
        return YES;
    }
    
    uint64_t ext = 0;

    while (*paths) {
        if (hasFileExtension(sandbox, *paths, ent_key)) {
            printf("[sbex][i] Pid %d already has '%s', skipping\n", pid, *paths);
            ++paths;
            continue;
        }
        
        printf("[sbex][i] Adding '%s' file extension for key '%s'\n", *paths, ent_key);
        ext = createFileExtension(*paths, ext);
        if (ext == 0) {
            printf("[sbex][-] Adding (%s) failed, panic!\n", *paths);
        }
        printf("[sbex][-] Adding (%s) success! ext: 0x%llx, sandbox:0x%llx, ent_key: %s\n", *paths, ext, sandbox, ent_key);
        ++paths;
    }
    
    if (ext != 0) {
        printf("[sbex][i] Adding exceptions on pid %d's sandbox\n", pid);
        extension_add(ext, sandbox, ent_key);
    }
    return (ext != 0);
}

int extension_create_file(uint64_t saveto, uint64_t sb, const char *path, size_t path_len, uint32_t subtype) {
    size_t len = strlen(path) + 1;
    
    uint64_t kstr = 0;
    kmalloc(&kstr, len);
    kwrite_buf_univ(kstr, path, len);
    
    int ret = 0;
    kcall(&ret, 0xFFFFFFF0069C4FF4 + kslide, 5, &saveto, sb, kstr, (uint64_t)path_len, (uint64_t)subtype);

    kdealloc(kstr, len);
    
    printf("extension_create_file ret: %d\n", ret);
    
    return ret;
}

int extension_add2(uint64_t ext, uint64_t sb, const char *desc) {
    size_t len = strlen(desc) + 1;
    
    uint64_t kstr = 0;
    kmalloc(&kstr, len);
    kwrite_buf_univ(kstr, desc, len);
    
    int ret = 0;
    kcall(&ret, 0xFFFFFFF0069C5270 + kslide, 3, ext, sb, kstr);
    
    kdealloc(kstr, len);
    
    printf("extension_add2 ret: %d\n", ret);
    
    return ret;
}

#define FILE_READ_WRITE_EXC_KEY "com.apple.security.exception.files.absolute-path.read-write"
bool set_sandbox_exceptions(uint64_t sandbox) {
//    uint64_t ext_kptr = smalloc(sizeof(uint64_t));
    
    uint64_t ext_kptr = 0;
    kmalloc(&ext_kptr, sizeof(uint64_t));
    
    extension_create_file(ext_kptr, sandbox, FAKEROOTDIR, strlen(FAKEROOTDIR), 0);
    uint64_t ext = kernel_read64(ext_kptr);
    extension_add2(ext, sandbox, FILE_READ_WRITE_EXC_KEY);
    return true;
}
