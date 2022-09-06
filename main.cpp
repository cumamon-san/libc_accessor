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

#define DEBUG(fmt, args...) printf(fmt "\n", ## args)
#define DEBUG_VAR(var, fmt) DEBUG(#var " = " fmt, var)


class dw_libc_wrapper_t {
public:
    dw_libc_wrapper_t();
    DIR *opendir(const char *path)    { return opendir_ptr_(path); }
    struct dirent *readdir(DIR *dir)  { return readdir_ptr_(dir);  }

private:
    static int dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t, void *data);

    decltype(&::opendir) opendir_ptr_;
    decltype(&::readdir) readdir_ptr_;
};

dw_libc_wrapper_t::dw_libc_wrapper_t()
    : opendir_ptr_(nullptr)
    , readdir_ptr_(nullptr)
{
    dl_iterate_phdr(dl_iterate_phdr_cb, this);
    assert(opendir_ptr_);
    assert(readdir_ptr_);
}


// For unknown reason, addresses are sometimes relative sometimes absolute.
static ElfW(Addr) correct_address(ElfW(Addr) base, ElfW(Addr) ptr) {
    return ptr > base ? ptr : base + ptr;
};

static size_t count_hash_entries(const ElfW(Word) *hash)
{
    const ElfW(Word) nbucket = hash[0];
    const ElfW(Word) nchain = hash[1];

    DEBUG_VAR(nbucket, "%d");
    DEBUG_VAR(nchain, "%d");

    return nchain;
}

template <typename T>
inline void set_if_empty(T& func_ptr, ElfW(Addr) addr)
{
    if(!func_ptr) func_ptr = (T)addr;
}

int dw_libc_wrapper_t::dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t, void *data)
{
    if(!strstr(info->dlpi_name, "/libc.so."))
        return 0;

    auto wrapper = reinterpret_cast<dw_libc_wrapper_t *>(data);
    DEBUG("Use libc from: %s", info->dlpi_name);

    for(int j = 0; j < info->dlpi_phnum; j++) {
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
                if(ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
                    continue;

                const char *str = &strtab[sym->st_name];
                if(!strcmp(str, "opendir")) {
                    DEBUG("Found '%s'", str);
                    set_if_empty(wrapper->opendir_ptr_, info->dlpi_addr + sym->st_value);
                }
                else if(!strcmp(str, "readdir")) {
                    DEBUG("Found '%s'", str);
                    set_if_empty(wrapper->readdir_ptr_, info->dlpi_addr + sym->st_value);
                }
            }
            break;
        }
    }

    return 0;
}


static void list_current_dir_by_libc()
{
    DEBUG("\nList current dir with directly libc");
    dw_libc_wrapper_t libc;
    DIR *dir = libc.opendir(".");
    if(!dir) {
        DEBUG("error: cannot open dir '.'");
        exit(EXIT_FAILURE);
    }
    struct dirent *dirent;
    while((dirent = libc.readdir(dir))) {
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


int main(int argc, char **argv)
{
    list_current_dir();
    list_current_dir_by_libc();
    return 0;
}

