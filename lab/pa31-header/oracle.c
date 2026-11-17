// Export-only PA31 header oracle; no native code patches or internal calls.
// Build: x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 oracle.c -lbcrypt -o oracle.exe
// oracle.exe create|create-no-hash|create-pa30 DLL SOURCE TARGET OUTPUT_DIRECTORY
// oracle.exe probe DLL SOURCE DELTA EXPECTED_TARGET OUTPUT_DIRECTORY
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const void *data; SIZE_T size; BOOL editable; } DeltaInput;
typedef struct { void *data; SIZE_T size; } DeltaOutput;
typedef struct { BYTE *bytes; size_t size; } Blob;
typedef BOOL (WINAPI *CreateFn)(int64_t, int64_t, int64_t, DeltaInput, DeltaInput,
                              DeltaInput, DeltaInput, DeltaInput, FILETIME *, ULONG, DeltaOutput *);
typedef BOOL (WINAPI *ApplyFn)(int64_t, DeltaInput, DeltaInput, DeltaOutput *);
typedef BOOL (WINAPI *InfoFn)(DeltaInput, void *, SIZE_T);
typedef BOOL (WINAPI *FreeFn)(void *);
typedef struct {
    uint32_t structure_size, format_version, minimum_client_version, reserved;
    int64_t file_type_set, file_type, flags, target_size;
    FILETIME target_time;
    uint32_t hash_algorithm, target_hash_size;
    BYTE target_hash[32];
    uint32_t source_hash_size;
    BYTE source_hash[32];
} HeaderInfo;
_Static_assert(sizeof(void *) == 8 && sizeof(DeltaInput) == 24 && sizeof(DeltaOutput) == 16,
               "Windows x64 delta ABI required");
_Static_assert(sizeof(HeaderInfo) == 0x88 && offsetof(HeaderInfo, source_hash_size) == 0x60
               && offsetof(HeaderInfo, hash_algorithm) == 0x38, "extended info ABI");

static const char dll_hash[] = "b2abf7125b94c5061f4044f747e23477237cb28c7a25ceae74f3d6dcbc887958";
enum { LIMIT = 16 * 1024 * 1024, PA31_CREATE_FLAG = 0x10000000 };

static void fail(const char *reason) {
    fprintf(stderr, "%s (Windows error %lu)\n", reason, GetLastError());
    ExitProcess(2);
}
static Blob load(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) fail("open input");
    long n = ftell(file);
    if (n < 0 || n > LIMIT || fseek(file, 0, SEEK_SET)) fail("input size");
    Blob blob = {malloc(n ? (size_t)n : 1), (size_t)n};
    if (!blob.bytes || fread(blob.bytes, 1, blob.size, file) != blob.size || fclose(file)) fail("read input");
    return blob;
}
static void hash(Blob blob, char result[65]) {
    if (blob.size > LIMIT) fail("hash input size");
    BCRYPT_ALG_HANDLE algorithm;
    BYTE digest[32];
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0
        || BCryptHash(algorithm, NULL, 0, blob.bytes, (ULONG)blob.size, digest, 32) < 0)
        fail("SHA256");
    BCryptCloseAlgorithmProvider(algorithm, 0);
    for (size_t i = 0; i < 32; i++) sprintf(result + 2 * i, "%02x", digest[i]);
}
static void hash_module(HMODULE module, char result[65]) {
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(module, path, MAX_PATH);
    if (!n || n >= MAX_PATH) fail("module path");
    Blob file = load(path); hash(file, result); free(file.bytes);
}
static void output_path(const char *directory, const char *name, char path[MAX_PATH]) {
    int n = snprintf(path, MAX_PATH, "%s/%s", directory, name);
    if (n < 0 || n >= MAX_PATH) fail("output path too long");
}
static FILE *output(const char *directory, const char *name) {
    char path[MAX_PATH]; output_path(directory, name, path);
    FILE *file = fopen(path, "wb");
    if (!file) fail("open output");
    return file;
}
static void save(const char *directory, const char *name, Blob blob) {
    FILE *file = output(directory, name);
    if (fwrite(blob.bytes, 1, blob.size, file) != blob.size || fclose(file)) fail("write output");
}
static Blob native_output(DeltaOutput output) {
    if (output.size > LIMIT || (output.size && !output.data)) fail("native output size");
    return (Blob){output.data, output.size};
}

int main(int argc, char **argv) {
    BOOL create = argc == 6 && (!strcmp(argv[1], "create") || !strcmp(argv[1], "create-no-hash")
                               || !strcmp(argv[1], "create-pa30"));
    BOOL probe = argc == 7 && !strcmp(argv[1], "probe");
    if (!create && !probe) {
        fprintf(stderr, "usage: oracle.exe create|create-no-hash|create-pa30 DLL SOURCE TARGET OUTPUT_DIRECTORY\n"
                        "       oracle.exe probe DLL SOURCE DELTA EXPECTED_TARGET OUTPUT_DIRECTORY\n");
        return 1;
    }
    const char *directory = argv[argc - 1];
    DWORD attributes = GetFileAttributesA(directory);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) fail("output directory");
    char manifest[MAX_PATH], pending[MAX_PATH];
    output_path(directory, "observation.json", manifest);
    output_path(directory, "observation.json.tmp", pending);
    if (!DeleteFileA(manifest) && GetLastError() != ERROR_FILE_NOT_FOUND) fail("invalidate completion marker");
    Blob dll = load(argv[2]);
    char actual_hash[65], harness_hash[65]; hash(dll, actual_hash); free(dll.bytes);
    if (strcmp(actual_hash, dll_hash)) fail("DLL hash mismatch");
    char absolute[MAX_PATH];
    DWORD n = GetFullPathNameA(argv[2], MAX_PATH, absolute, NULL);
    if (!n || n >= MAX_PATH) fail("DLL absolute path");
    HMODULE module = LoadLibraryExA(absolute, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) fail("load UpdateCompression");
    hash_module(module, actual_hash);
    if (strcmp(actual_hash, dll_hash)) fail("loaded DLL hash mismatch");
    hash_module(NULL, harness_hash);
    CreateFn create_delta = (CreateFn)(void *)GetProcAddress(module, "CreateDeltaB");
    ApplyFn apply = (ApplyFn)(void *)GetProcAddress(module, "ApplyDeltaB");
    InfoFn info = (InfoFn)(void *)GetProcAddress(module, "GetDeltaInfoExB");
    FreeFn release = (FreeFn)(void *)GetProcAddress(module, "DeltaFree");
    if (!create_delta || !apply || !info || !release) fail("missing native exports");
    Blob source = load(argv[3]), supplied = load(argv[4]);
    Blob expected = create ? supplied : load(argv[5]);
    char source_hash[65], delta_hash[65], target_hash[65];
    hash(source, source_hash); hash(expected, target_hash);
    DeltaInput source_input = {source.bytes, source.size, FALSE};
    DeltaOutput created = {0}, applied = {0};
    Blob delta = supplied;
    uint32_t hash_algorithm = !strcmp(argv[1], "create-no-hash") ? 0 : 0x800c;
    uint32_t create_flags = !strcmp(argv[1], "create-pa30") ? 0 : PA31_CREATE_FLAG;
    const char *delta_name = create && !create_flags ? "delta.pa30" : "delta.pa31";
    if (create) {
        DeltaInput target_input = {expected.bytes, expected.size, FALSE}, empty = {0};
        FILETIME timestamp = {0};
        SetLastError(0);
        BOOL create_ok = create_delta(1, create_flags, 0, source_input, target_input, empty, empty, empty,
                                      &timestamp, hash_algorithm, &created);
        DWORD create_error = GetLastError();
        if (!create_ok) {
            save(directory, "source.bin", source); save(directory, "target.bin", expected);
            FILE *meta = output(directory, "observation.json.tmp");
            if (fprintf(meta,
                "{\n  \"schema\": 1,\n  \"dll_sha256\": \"%s\",\n  \"harness_sha256\": \"%s\",\n"
                "  \"operation\": \"%s\",\n  \"native_create_flags\": %u,\n  \"hash_algorithm\": %u,\n"
                "  \"create_ok\": false,\n  \"create_error\": %lu\n}\n",
                dll_hash, harness_hash, argv[1], create_flags, hash_algorithm, create_error) < 0 || fclose(meta))
                fail("write creation rejection");
            if (!MoveFileExA(pending, manifest, MOVEFILE_WRITE_THROUGH)) fail("publish creation rejection");
            printf("create=0 error=%lu\n", create_error);
            free(source.bytes); free(supplied.bytes); FreeLibrary(module);
            return 0;
        }
        delta = native_output(created);
        if (delta.size < 4 || memcmp(delta.bytes, create_flags ? "PA31" : "PA30", 4))
            fail("create flags did not select expected format");
    }
    hash(delta, delta_hash);
    DeltaInput delta_input = {delta.bytes, delta.size, FALSE};
    HeaderInfo header;
    memset(&header, 0xa5, sizeof header);
    SetLastError(0);
    BOOL info_ok = info(delta_input, &header, sizeof header);
    DWORD info_error = GetLastError();
    SetLastError(0);
    BOOL apply_ok = apply(0, source_input, delta_input, &applied);
    DWORD apply_error = GetLastError();
    Blob result = apply_ok ? native_output(applied) : (Blob){0};
    BOOL exact = apply_ok && result.size == expected.size
        && (!result.size || !memcmp(result.bytes, expected.bytes, result.size));
    if (create && (!info_ok || !exact)) fail("native create control failed");
    hash(source, actual_hash);
    if (strcmp(actual_hash, source_hash)) fail("native modified noneditable source input");
    hash(delta, actual_hash);
    if (strcmp(actual_hash, delta_hash)) fail("native modified noneditable delta input");
    hash(expected, actual_hash);
    if (strcmp(actual_hash, target_hash)) fail("native modified expected target input");
    save(directory, "source.bin", source);
    save(directory, delta_name, delta);
    save(directory, "target.bin", expected);
    if (info_ok) save(directory, "header-info.bin", (Blob){(BYTE *)&header, sizeof header});
    if (apply_ok) save(directory, "applied.bin", result);
    char result_hash[65] = "", header_hash[65] = "";
    if (apply_ok) hash(result, result_hash);
    if (info_ok) hash((Blob){(BYTE *)&header, sizeof header}, header_hash);
    if ((created.data && !release(created.data)) || (applied.data && !release(applied.data))) fail("DeltaFree");
    FILE *meta = output(directory, "observation.json.tmp");
    if (fprintf(meta,
        "{\n  \"schema\": 1,\n  \"dll_sha256\": \"%s\",\n  \"harness_sha256\": \"%s\",\n"
        "  \"operation\": \"%s\",\n  \"native_create_flags\": %u,\n  \"info_output_size\": %llu,\n"
        "  \"delta_file\": \"%s\",\n"
        "  \"source_sha256\": \"%s\",\n  \"delta_sha256\": \"%s\",\n  \"target_sha256\": \"%s\",\n"
        "  \"get_info_ok\": %s,\n  \"get_info_error\": %lu,\n  \"apply_ok\": %s,\n"
        "  \"apply_error\": %lu,\n  \"target_equal\": %s,\n  \"applied_sha256\": \"%s\",\n"
        "  \"header_info_sha256\": \"%s\",\n  \"noneditable_inputs_unchanged\": true,\n"
        "  \"info_structure_size\": %u,\n  \"info_format_version\": %u,\n"
        "  \"info_minimum_client_version\": %u,\n  \"info_hash_algorithm\": %u,\n"
        "  \"info_source_hash_size\": %u,\n  \"info_target_hash_size\": %u\n}\n",
        dll_hash, harness_hash, argv[1], create ? create_flags : 0, (unsigned long long)sizeof header, delta_name,
        source_hash, delta_hash, target_hash, info_ok ? "true" : "false", info_error,
        apply_ok ? "true" : "false", apply_error, exact ? "true" : "false", result_hash, header_hash,
        info_ok ? header.structure_size : 0, info_ok ? header.format_version : 0,
        info_ok ? header.minimum_client_version : 0, info_ok ? header.hash_algorithm : 0,
        info_ok ? header.source_hash_size : 0, info_ok ? header.target_hash_size : 0) < 0 || fclose(meta))
        fail("write observation");
    if (!MoveFileExA(pending, manifest, MOVEFILE_WRITE_THROUGH)) fail("publish observation");
    printf("info=%d error=%lu apply=%d error=%lu exact=%d\n", info_ok, info_error, apply_ok, apply_error, exact);
    free(source.bytes); free(supplied.bytes); if (probe) free(expected.bytes);
    FreeLibrary(module);
    return 0;
}
