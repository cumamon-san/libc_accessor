#ifdef __linux__
#   ifndef _GNU_SOURCE
#       warning _GNU_SOURCE undefined
#       define _GNU_SOURCE
#   endif
#endif

#include <assert.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// For unknown reason, addresses are sometimes relative sometimes absolute.
static inline void *correct_address(uintptr_t base, uintptr_t ptr) {
    return ptr > base ? ptr : base + ptr;
};

static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
    // data is copy of 2nd arg in dl_iterate_phdr
    // you can use it for your lib name as I did
    const char *libname_prefix = (const char *)data;

    printf("Lookup '%s' in '%s'\n", libname_prefix, info->dlpi_name);

    // if current elf's name contains your lib
    if(strstr(info->dlpi_name, libname_prefix)) {
        printf("loaded %s from: %s\n", libname_prefix, info->dlpi_name);

        for (int j = 0; j < info->dlpi_phnum; j++) {
            // we need to save dyanmic section since it contains symbolic table
            if(info->dlpi_phdr[j].p_type == PT_DYNAMIC) {
                Elf64_Sym *symtab = NULL;
                char *strtab = NULL;
                int symentries = 0; // size of one Elf64_Sym
                Elf64_Dyn *dyn = (typeof(dyn))(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
                for(int k = 0; k < info->dlpi_phdr[j].p_memsz / sizeof(Elf64_Dyn); ++k) {
                    switch(dyn[k].d_tag) {
                        case DT_SYMTAB:
                            symtab = correct_address(info->dlpi_addr, (Elf64_Sym *)dyn[k].d_un.d_ptr);
                            break;
                        case DT_STRTAB:
                            strtab = correct_address(info->dlpi_addr, (char*)dyn[k].d_un.d_ptr);
                            break;
                        case DT_SYMENT:
                            symentries = dyn[k].d_un.d_val;
                            break;
                    }
                }

                assert(symtab);
                assert(strtab);
                assert(symentries);

                printf("DT_SYMENT = %d, sizeof(Elf64_Sym) = %d\n", symentries, sizeof(Elf64_Sym));

                int size = strtab - (char *)symtab;
                // for each string in table
                printf("size / symentries = %d\n", size / symentries);
                for(int k = 0; k < size / symentries; ++k) {
                    Elf64_Sym *sym = &symtab[k];
                    if(ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
//                        printf("type not func: %d, skip\n", ELF64_ST_TYPE(sym->st_info));
                        continue;
                    }

//                    printf("sym->st_name = %#lx\n", sym->st_name);
                    char *str = &strtab[sym->st_name];
//                    printf("str = %s (%p)\n", str, str);
                    if(str && !strcmp(str, "printf")) {
                        printf("Found 'printf'\n");
                        typeof(&printf) printf_ptr = (typeof(printf_ptr))(info->dlpi_addr + sym->st_value);
                        printf_ptr("Use printf_ptr #%d\n", 1);
                         exit(0);
                    }
                }
                break;
            }
        }
    }
    return 0;
}


int main()
{
    const char *libname = "libc.so.";
    dl_iterate_phdr(callback, (void*)libname);
    return 0;
}

