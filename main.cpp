// #ifndef _GNU_SOURCE
// #   warning _GNU_SOURCE undefined
// #   define _GNU_SOURCE
// #endif

#include <array>
#include <chrono>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include <dirent.h>
#include <link.h>
#include <unistd.h>

using namespace std::string_literals;

#define ERROR(X) do { std::cerr << "ERROR: " << __func__ << ": " << X << std::endl; } while(0)
#define PRINT(X) do { std::cout << X << std::endl; } while(0)
#define DEBUG(X) do { std::cout << "DEBUG: " << X << std::endl; } while(0)
#define DEBUG_VAR(X) DEBUG(#X " = " << X)

#define THROW(X) throw std::runtime_error(__func__ + ": "s + X)
#define THROW_WITH_ERRNO(X) THROW(X + ": " + strerror(errno))

// Elf macros
#if __ELF_NATIVE_CLASS == 32
#   define ELF_ST_TYPE ELF32_ST_TYPE
#else
#   define ELF_ST_TYPE ELF64_ST_TYPE
#endif


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

static size_t count_hash_entries(const ElfW(Word) *hash)
{
    ElfW(Word) nchain = hash[1];
    return nchain;
}

template <typename T>
static inline T *shift_ptr(T* ptr, size_t offset)
{
    return reinterpret_cast<T*>(reinterpret_cast<const char*>(ptr) + offset);
}

typedef struct {
    ElfW(Word) nbuckets;
    ElfW(Word) symoffset;
    ElfW(Word) bloom_size;
    ElfW(Word) bloom_shift;
} gnu_hash_hdr_t;

static size_t count_gnu_hash_entries(const ElfW(Word) *gnu_hash)
{
    auto hdr = reinterpret_cast<const gnu_hash_hdr_t *>(gnu_hash);
    auto buckets = shift_ptr(gnu_hash, sizeof(gnu_hash_hdr_t) + sizeof(ElfW(Xword)) * hdr->bloom_size);
    auto chains = shift_ptr(buckets, sizeof(*buckets) * hdr->nbuckets);

    // Locate the chain that handles the largest index bucket.
    ElfW(Word) last_symbol = 0;
    for(ElfW(Word) i = 0; i < hdr->nbuckets; ++i)
        last_symbol = std::max(buckets[i], last_symbol);
    if(last_symbol < hdr->symoffset)
        return last_symbol;

    // Walk the bucket's chain to add the chain length to the total.
    while(true) {
        ElfW(Word) chain_entry = chains[last_symbol - hdr->symoffset];
        ++last_symbol;
        if(chain_entry & 1)
            break;
    }
    return last_symbol;
}

// For unknown reason, addresses are sometimes relative sometimes absolute.
static ElfW(Addr) correct_address(ElfW(Addr) base, ElfW(Addr) ptr) {
    return ptr > base ? ptr : base + ptr;
};

template <typename T>
inline void assign_if_empty(T& var, ElfW(Addr) addr)
{
    if(!var) var = reinterpret_cast<T>(addr);
}

int dw_libc_wrapper_t::dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t, void *data)
{
    DEBUG("lookup '" << info->dlpi_name << '\'');
    if(!strstr(info->dlpi_name, "/libc.so."))
        return 0;

    DEBUG("use libc from '" << info->dlpi_name << "' (" << (void *)info->dlpi_addr << ')');
    auto wrapper = reinterpret_cast<dw_libc_wrapper_t*>(data);

    for(int j = 0; j < info->dlpi_phnum; j++) {
        if(info->dlpi_phdr[j].p_type == PT_DYNAMIC) {
            const char *strtab = nullptr;
            const ElfW(Sym) *symtab = nullptr;
            const ElfW(Word) *hash = nullptr;
            const ElfW(Word) *gnu_hash = nullptr;
            auto dyn = reinterpret_cast<ElfW(Dyn)*>(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
            auto phdr_entry_count = info->dlpi_phdr[j].p_memsz / sizeof(*dyn);
            for(int k = 0; k < phdr_entry_count; ++k) {
                switch(dyn[k].d_tag) {
                    case DT_SYMTAB:
                        DEBUG("found DT_SYMTAB");
                        assign_if_empty(symtab , correct_address(info->dlpi_addr, dyn[k].d_un.d_ptr));
                        break;
                    case DT_STRTAB:
                        DEBUG("found DT_STRTAB");
                        assign_if_empty(strtab , correct_address(info->dlpi_addr, dyn[k].d_un.d_ptr));
                        break;
                    case DT_HASH:
                        DEBUG("found DT_HASH");
                        assign_if_empty(hash , correct_address(info->dlpi_addr, dyn[k].d_un.d_ptr));
                        break;
                    case DT_GNU_HASH:
                        DEBUG("found DT_GNU_HASH");
                        assign_if_empty(gnu_hash , correct_address(info->dlpi_addr, dyn[k].d_un.d_ptr));
                        break;
                }
            }

            assert(symtab);
            assert(strtab);
            assert(hash || gnu_hash);

            size_t hash_size = hash? count_hash_entries(hash) : 0;
            size_t gnu_hash_size = gnu_hash? count_gnu_hash_entries(gnu_hash) : 0;
            if(hash && gnu_hash) assert(hash_size == gnu_hash_size);

            size_t symtab_size = std::max(hash_size, gnu_hash_size);

            DEBUG_VAR(hash_size);
            DEBUG_VAR(gnu_hash_size);
            DEBUG_VAR(symtab_size);

            for(int k = 0; k < symtab_size; ++k) {
                auto *sym = &symtab[k];
                if(ELF_ST_TYPE(sym->st_info) != STT_FUNC)
                    continue;

                auto str = &strtab[sym->st_name];
                if(!strcmp(str, "opendir")) {
                    DEBUG("found '" << str << '\'');
                    assign_if_empty(wrapper->opendir_ptr_, info->dlpi_addr + sym->st_value);
                }
                else if(!strcmp(str, "readdir")) {
                    DEBUG("found '" << str << '\'');
                    assign_if_empty(wrapper->readdir_ptr_, info->dlpi_addr + sym->st_value);
                }
            }
            break;
        }
    }

    return -1;
}


static void list_current_dir_by_libc()
{
    PRINT("\nList current dir directly with libc");
    dw_libc_wrapper_t libc;
    DIR *dir = libc.opendir(".");
    if(!dir) {
        ERROR("cannot open dir '.'");
        return;
    }
    struct dirent *dirent;
    while((dirent = libc.readdir(dir))) {
        PRINT("List entry: " << dirent->d_name);
    }
}

static void list_current_dir()
{
    PRINT("\nList current dir with default funcs");
    DIR *dir = opendir(".");
    if(!dir) {
        ERROR("cannot open dir '.'");
        return;
    }
    struct dirent *dirent;
    while((dirent = readdir(dir))) {
        PRINT("List entry: " << dirent->d_name);
    }
}

int main()
{
    list_current_dir();
    list_current_dir_by_libc();
    return 0;
}
