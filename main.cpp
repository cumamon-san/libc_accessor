// #ifndef _GNU_SOURCE
// #   warning _GNU_SOURCE undefined
// #   define _GNU_SOURCE
// #endif

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <link.h>

#include <dirent.h>

// static int callback(struct dl_phdr_info *info, size_t size, void *data) {
//     const char *type;
//     int p_type, j;
//     printf("Name: \"%s\" (%d segments)\n", info->dlpi_name, info->dlpi_phnum);
//
//     for (j = 0; j < info->dlpi_phnum; j++) {
//         p_type = info->dlpi_phdr[j].p_type;
//         type =  (p_type == PT_LOAD) ? "PT_LOAD" :
//         (p_type == PT_DYNAMIC) ? "PT_DYNAMIC" :
//         (p_type == PT_INTERP) ? "PT_INTERP" :
//         (p_type == PT_NOTE) ? "PT_NOTE" :
//         (p_type == PT_INTERP) ? "PT_INTERP" :
//         (p_type == PT_PHDR) ? "PT_PHDR" :
//         (p_type == PT_TLS) ? "PT_TLS" :
//         (p_type == PT_GNU_EH_FRAME) ? "PT_GNU_EH_FRAME" :
//         (p_type == PT_GNU_STACK) ? "PT_GNU_STACK" :
//         (p_type == PT_GNU_RELRO) ? "PT_GNU_RELRO" : NULL;
//
//
//         printf("    %2d: [%14p; memsz:%7lx] flags: 0x%x; ", j,
//                (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),
//                info->dlpi_phdr[j].p_memsz,
//                info->dlpi_phdr[j].p_flags);
//         if (type != NULL)
//             printf("%s\n", type);
//         else
//             printf("[other (0x%x)]\n", p_type);
//     }
//
//
//     return 0;
// }
//
// int main(int argc, char *argv[]) {
//     dl_iterate_phdr(callback, NULL);
//     exit(EXIT_SUCCESS);
// }

#define DEBUG(fmt, args...) printf(fmt "\n", ## args)
#define DEBUG_VAR(var, fmt) DEBUG(#var " = " fmt, var)

// For unknown reason, addresses are sometimes relative sometimes absolute.
static inline void *correct_address(Elf64_Addr base, Elf64_Addr ptr) {
    return (void *)(ptr > base ? ptr : base + ptr);
};

static size_t count_hash_entries(const ElfW(Word) *hash)
{
    const ElfW(Word) nbucket = hash[0];
    const ElfW(Word) nchain = hash[1];

    DEBUG_VAR(nbucket, "%d");
    DEBUG_VAR(nchain, "%d");

    return nchain;
}

static decltype(&opendir) opendir_ptr = nullptr;
static decltype(&readdir) readdir_ptr = nullptr;

static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
    // data is copy of 2nd arg in dl_iterate_phdr
    // you can use it for your lib name as I did
    const char * libname_prefix = (const char *)data;

    DEBUG("Lookup '%s' in '%s'", libname_prefix, info->dlpi_name);

    // if current elf's name contains your lib
    if(strstr(info->dlpi_name, libname_prefix)) {
        DEBUG("loaded %s from: %s", libname_prefix, info->dlpi_name);

        for(int j = 0; j < info->dlpi_phnum; j++) {
            // we need to save dyanmic section since it contains symbolic table
            if(info->dlpi_phdr[j].p_type == PT_DYNAMIC) {
                const ElfW(Sym) *symtab = NULL;
                const ElfW(Word) *hash = nullptr;
                const ElfW(Word) *gnu_hash = nullptr;
                const char *strtab = NULL;
                auto dyn = (Elf64_Dyn *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
                for(int k = 0; k < info->dlpi_phdr[j].p_memsz / sizeof(Elf64_Dyn); ++k) {
                    switch(dyn[k].d_tag) {
                        case DT_SYMTAB:
                            DEBUG("Found DT_SYMTAB");
                            symtab = (decltype(symtab))correct_address(info->dlpi_addr, dyn[k].d_un.d_ptr);
                            break;
                        case DT_STRTAB:
                            DEBUG("Found DT_STRTAB");
                            strtab = (decltype(strtab))correct_address(info->dlpi_addr, dyn[k].d_un.d_ptr);
                            break;
                        case DT_HASH:
                            DEBUG("Found DT_HASH");
                            hash = (decltype(hash))correct_address(info->dlpi_addr, dyn[k].d_un.d_ptr);
                            break;
                        case DT_GNU_HASH:
                            DEBUG("Found DT_GNU_HASH");
                            gnu_hash = (decltype(gnu_hash))correct_address(info->dlpi_addr, dyn[k].d_un.d_ptr);
                            break;
                    }
                }

                assert(symtab);
                assert(strtab);
                assert(hash || gnu_hash);

                int hash_size = hash? count_hash_entries(hash) : 0;
                DEBUG_VAR(hash_size, "%d");
                for(int k = 0; k < hash_size; ++k) {
                    const ElfW(Sym) *sym = &symtab[k];
                    if(ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
//                        printf("type not func: %d, skip\n", ELF64_ST_TYPE(sym->st_info));
                        continue;
                    }

                    const char *str = &strtab[sym->st_name];
                    if(!str)
                        continue;

                    if(!strcmp(str, "printf")) {
                        DEBUG("Found '%s'", str);
                        auto printf_ptr = decltype(&printf)(info->dlpi_addr + sym->st_value);
                        printf_ptr("Use printf_ptr: OK\n");
                    }
                    if(!strcmp(str, "opendir")) {
                        DEBUG("Found '%s'", str);
                        opendir_ptr = decltype(opendir_ptr)(info->dlpi_addr + sym->st_value);
                    }
                    if(!strcmp(str, "readdir")) {
                        DEBUG("Found '%s'", str);
                        readdir_ptr = decltype(readdir_ptr)(info->dlpi_addr + sym->st_value);
                    }
                }
                break;
            }
        }
    }
    return 0;
}


static void list_current_dir_by_libc()
{
    DEBUG("\nList current dir with directly libc");
    assert(opendir_ptr);
    assert(readdir_ptr);
    DIR *dir = opendir_ptr(".");
    if(!dir) {
        DEBUG("error: cannot open dir '.'");
        exit(EXIT_FAILURE);
    }
    struct dirent *dirent;
    while((dirent = readdir_ptr(dir))) {
        DEBUG("List entry: %s", dirent->d_name);
    }
}

static void list_current_dir()
{
    DEBUG("\nList current dir with default funcs");
    DIR *dir = opendir(".");
    if(!dir) {
        DEBUG("error: cannot open dir '.'");
        exit(EXIT_FAILURE);
    }
    struct dirent *dirent;
    while((dirent = readdir(dir))) {
        DEBUG("List entry: %s", dirent->d_name);
    }
}

static void fill_libc_func(void)
{
    const char *libname = "/libc.so.";
    dl_iterate_phdr(callback, (void*)libname);
}

int main(int argc, char **argv)
{
    fill_libc_func();
    list_current_dir();
    list_current_dir_by_libc();
    return 0;
}

