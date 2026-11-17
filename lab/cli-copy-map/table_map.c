// Native fixed-width CLI table map oracle for the pinned msdelta DLL.
// Synthetic stack objects expose only fields independently verified in disassembly.
// Output capacity 128 prevents native allocation/free; no constructors are invoked.
#include <windows.h>
#include <bcrypt.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { int64_t source, target; } Entry;
typedef struct { uint64_t unused[2], count, capacity; Entry *entries; uint64_t sorted; } RiftView;
typedef struct { unsigned char unused[0x50]; RiftView *output; } Component;
typedef void (*AddTableFn)(Component *, int64_t, int64_t, uint32_t, const RiftView *);
_Static_assert(offsetof(RiftView, count) == 0x10, "count offset");
_Static_assert(offsetof(RiftView, entries) == 0x20, "entries offset");
_Static_assert(offsetof(Component, output) == 0x50, "output offset");
static const char pinned_hash[] = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb";
static void fail(const char *message) {
    fprintf(stderr, "%s (Windows error %lu)\n", message, GetLastError());
    exit(2);
}

static void file_hash(const char *path, char result[65]) {
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) fail("open hash input");
    long size = ftell(file);
    if (size < 0 || size > 32 * 1024 * 1024 || fseek(file, 0, SEEK_SET)) fail("size hash input");
    BYTE *bytes = malloc(size ? (size_t)size : 1);
    if (!bytes || fread(bytes, 1, (size_t)size, file) != (size_t)size || fclose(file)) fail("read hash input");
    BCRYPT_ALG_HANDLE algorithm;
    BYTE digest[32];
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0
        || BCryptHash(algorithm, NULL, 0, bytes, (ULONG)size, digest, sizeof digest) < 0)
        fail("hash input");
    BCryptCloseAlgorithmProvider(algorithm, 0);
    free(bytes);
    for (size_t i = 0; i < sizeof digest; ++i) sprintf(result + i * 2, "%02x", digest[i]);
}


static void pairs(FILE *f, const Entry *entries, size_t count) {
    fputc('[', f);
    for (size_t i = 0; i < count; ++i)
        fprintf(f, "%s[\"%" PRId64 "\",\"%" PRId64 "\"]", i ? "," : "", entries[i].source, entries[i].target);
    fputc(']', f);
}
static void emit(FILE *f, AddTableFn fn, const char *name, unsigned rva,
                 Entry *entries, size_t count, int64_t source_base, int64_t target_base, uint32_t width, BOOL first) {
    Entry storage[128]; memset(storage, 0xa5, sizeof storage);
    Entry original[16]; if (count > 16) fail("input capacity");
    if (count) memcpy(original, entries, count * sizeof *entries);
    RiftView input = {{0, 0}, count, count, entries, 1};
    RiftView output = {{0, 0}, 0, 128, storage, 1};
    Component component = {{0}, &output};
    fn(&component, source_base, target_base, width, &input);
    if (output.entries != storage || output.capacity != 128 || output.count > 128) fail("unexpected native allocation");
    if (input.count != count || (count && memcmp(original, entries, count * sizeof *entries))) fail("input changed");
    fprintf(f, "%s{\"name\":\"%s\",\"rva\":%u,\"source_base\":\"%" PRId64 "\",\"target_base\":\"%" PRId64 "\",\"row_width\":%u,\"input_unchanged\":true,\"input\":", first ? "" : ",\n", name, rva, source_base, target_base, width);
    pairs(f, entries, count); fputs(",\"output\":", f); pairs(f, storage, output.count); fputc('}', f);
}
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: table_map.exe DLL OUTPUT_JSON\n"); return 1; }
    char hash[65], own_hash[65], own[MAX_PATH], path[MAX_PATH];
    file_hash(argv[1], hash); if (strcmp(hash, pinned_hash)) fail("DLL hash");
    DWORD n = GetFullPathNameA(argv[1], MAX_PATH, path, NULL); if (!n || n >= MAX_PATH) fail("DLL path");
    n = GetModuleFileNameA(NULL, own, MAX_PATH); if (!n || n >= MAX_PATH) fail("own path");
    file_hash(own, own_hash);
    HMODULE dll = LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32); if (!dll) fail("load DLL");
    char loaded_path[MAX_PATH], loaded_hash[65];
    n = GetModuleFileNameA(dll, loaded_path, MAX_PATH);
    if (!n || n >= MAX_PATH) fail("loaded DLL path");
    file_hash(loaded_path, loaded_hash);
    if (strcmp(loaded_hash, pinned_hash)) fail("loaded DLL hash");
    FILE *f = fopen(argv[2], "wb"); if (!f) fail("output");
    fprintf(f, "{\"schema\":1,\"dll_sha256\":\"%s\",\"harness_sha256\":\"%s\",\"loaded_dll_sha256\":\"%s\",\"scope\":\"fixed-width AddTableMap only; synthetic layouts with preallocated output\",\"cases\":[\n", hash, own_hash, loaded_hash);
    Entry baseline[] = {{0,0},{1,2},{3,5}};
    Entry shifted[] = {{0,0},{1,3},{3,5}};
    Entry identity_first[] = {{0,0},{2,3}};
    Entry before_first[] = {{2,3},{4,7}};
    Entry zero_only[] = {{0,2}};
    Entry duplicate_one[] = {{0,0},{1,2},{1,4},{3,5}};
    Entry sentinel[] = {{0,0},{1,2},{UINT32_MAX,7},{(int64_t)UINT32_MAX+1,8}};
    Entry negative[] = {{-2,0},{0,2},{1,3},{4,8}};
    unsigned rvas[] = {0x1e590,0x1e6d0};
    for (size_t i = 0; i < 2; ++i) {
        AddTableFn fn = (AddTableFn)(void *)((BYTE *)dll + rvas[i]);
        emit(f,fn,"empty",rvas[i],NULL,0,908,1054,6,i==0);
        emit(f,fn,"memberref-first-row",rvas[i],baseline,3,908,1054,6,FALSE);
        emit(f,fn,"first-row-shifted",rvas[i],shifted,3,908,1054,6,FALSE);
        emit(f,fn,"identity-first-row",rvas[i],identity_first,2,908,1054,6,FALSE);
        emit(f,fn,"before-first-wrap",rvas[i],before_first,2,908,1054,6,FALSE);
        emit(f,fn,"zero-only",rvas[i],zero_only,1,908,1054,6,FALSE);
        emit(f,fn,"duplicate-first-row",rvas[i],duplicate_one,4,908,1054,6,FALSE);
        emit(f,fn,"source-sentinel",rvas[i],sentinel,4,908,1054,6,FALSE);
        emit(f,fn,"negative-prefix",rvas[i],negative,4,908,1054,6,FALSE);
        emit(f,fn,"guid-width",rvas[i],baseline,3,1224,1548,16,FALSE);
    }
    fputs("\n]}\n", f); if (ferror(f) || fclose(f)) fail("write"); FreeLibrary(dll); puts("20 fixed-width native table-map cases captured"); return 0;
}
