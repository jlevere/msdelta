// Export-only PA31 reverse-integrity oracle for the pinned native DLL.
// Build: x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 oracle.c -lbcrypt -o oracle.exe
// oracle.exe create-reverse DLL ORIGINAL NEW OUTPUT_DIRECTORY
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
typedef BOOL (WINAPI *GetReverseFn)(int64_t, DeltaInput, DeltaInput, const FILETIME *, DeltaOutput *, DeltaOutput *);
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

static BOOL equal(Blob a, Blob b) {
    return a.size == b.size && (!a.size || !memcmp(a.bytes, b.bytes, a.size));
}

int main(int argc, char **argv) {
    BOOL create = argc == 6 && !strcmp(argv[1], "create-reverse");
    BOOL probe = argc == 7 && !strcmp(argv[1], "probe");
    if (!create && !probe) {
        fprintf(stderr, "usage: oracle.exe create-reverse DLL ORIGINAL NEW OUTPUT_DIRECTORY\n"
                        "       oracle.exe probe DLL REFERENCE REVERSE_DELTA EXPECTED_TARGET OUTPUT_DIRECTORY\n");
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
    if (!n || n >= MAX_PATH) fail("DLL path");
    HMODULE module = LoadLibraryExA(absolute, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) fail("load UpdateCompression");
    hash_module(module, actual_hash);
    if (strcmp(actual_hash, dll_hash)) fail("loaded DLL hash mismatch");
    hash_module(NULL, harness_hash);
    CreateFn create_delta = (CreateFn)(void *)GetProcAddress(module, "CreateDeltaB");
    ApplyFn apply = (ApplyFn)(void *)GetProcAddress(module, "ApplyDeltaB");
    GetReverseFn get_reverse = (GetReverseFn)(void *)GetProcAddress(module, "ApplyDeltaGetReverseB");
    InfoFn info = (InfoFn)(void *)GetProcAddress(module, "GetDeltaInfoExB");
    FreeFn release = (FreeFn)(void *)GetProcAddress(module, "DeltaFree");
    if (!create_delta || !apply || !get_reverse || !info || !release) fail("missing native exports");
    Blob first = load(argv[3]), second = load(argv[4]);
    Blob source = create ? second : first;
    Blob expected = create ? first : load(argv[5]);
    Blob delta = second;
    char source_hash[65], target_hash[65], delta_hash[65];
    hash(source, source_hash); hash(expected, target_hash);
    DeltaOutput forward_delta = {0}, forward_control = {0}, reverse_target = {0}, reverse_delta = {0}, applied = {0};
    DWORD create_error = 0, forward_error = 0, reverse_error = 0;
    char forward_hash[65] = "", reverse_forward_hash[65] = "";
    if (create) {
        DeltaInput original_input = {first.bytes, first.size, FALSE};
        DeltaInput new_input = {second.bytes, second.size, FALSE}, empty = {0};
        FILETIME timestamp = {0};
        SetLastError(0);
        BOOL create_ok = create_delta(1, PA31_CREATE_FLAG, 0, original_input, new_input,
                                      empty, empty, empty, &timestamp, 0x800c, &forward_delta);
        create_error = GetLastError();
        if (!create_ok) fail("native forward CreateDeltaB failed");
        Blob forward = native_output(forward_delta);
        if (forward.size < 4 || memcmp(forward.bytes, "PA31", 4)) fail("forward is not PA31");
        hash(forward, forward_hash);
        DeltaInput forward_input = {forward.bytes, forward.size, FALSE};
        SetLastError(0);
        BOOL forward_ok = apply(0, original_input, forward_input, &forward_control);
        forward_error = GetLastError();
        if (!forward_ok || !equal(native_output(forward_control), second)) fail("native forward control differs");
        SetLastError(0);
        BOOL reverse_ok = get_reverse(0, original_input, forward_input, &timestamp, &reverse_target, &reverse_delta);
        reverse_error = GetLastError();
        if (!reverse_ok || !equal(native_output(reverse_target), second)) fail("native reverse-producing apply differs");
        delta = native_output(reverse_delta);
        if (delta.size < 4 || memcmp(delta.bytes, "PA31", 4)) fail("native reverse is not PA31");
        hash(forward, actual_hash);
        if (strcmp(actual_hash, forward_hash)) fail("native modified noneditable forward delta");
        hash(native_output(reverse_target), reverse_forward_hash);
        save(directory, "forward-source.bin", first);
        save(directory, "forward-target.bin", second);
        save(directory, "forward.pa31", forward);
        save(directory, "forward-applied.bin", native_output(forward_control));
        save(directory, "get-reverse-target.bin", native_output(reverse_target));
    }
    hash(delta, delta_hash);
    DeltaInput source_input = {source.bytes, source.size, FALSE};
    DeltaInput delta_input = {delta.bytes, delta.size, FALSE};
    HeaderInfo header;
    memset(&header, 0xa5, sizeof header);
    SetLastError(0);
    BOOL info_ok = info(delta_input, &header, sizeof header);
    DWORD info_error = GetLastError();
    if (create && (!info_ok || !(header.file_type_set & 0x100))) fail("native reverse flag missing");
    SetLastError(0);
    BOOL apply_ok = apply(0, source_input, delta_input, &applied);
    DWORD apply_error = GetLastError();
    Blob result = apply_ok ? native_output(applied) : (Blob){0};
    BOOL exact = apply_ok && equal(result, expected);
    if (create && !exact) fail("native reverse control differs from original");
    hash(source, actual_hash);
    if (strcmp(actual_hash, source_hash)) fail("native modified noneditable reference");
    hash(expected, actual_hash);
    if (strcmp(actual_hash, target_hash)) fail("native modified expected original");
    hash(delta, actual_hash);
    if (strcmp(actual_hash, delta_hash)) fail("native modified noneditable reverse delta");
    save(directory, "source.bin", source);
    save(directory, "delta.pa31", delta);
    save(directory, "target.bin", expected);
    if (info_ok) save(directory, "header-info.bin", (Blob){(BYTE *)&header, sizeof header});
    if (apply_ok) save(directory, "applied.bin", result);
    char result_hash[65] = "", header_hash[65] = "";
    if (apply_ok) hash(result, result_hash);
    if (info_ok) hash((Blob){(BYTE *)&header, sizeof header}, header_hash);
    DeltaOutput outputs[] = {forward_delta, forward_control, reverse_target, reverse_delta, applied};
    for (size_t index = 0; index < sizeof outputs / sizeof outputs[0]; index++) {
        if (outputs[index].data && !release(outputs[index].data)) fail("DeltaFree");
    }
    FILE *meta = output(directory, "observation.json.tmp");
    if (fprintf(meta,
        "{\n  \"schema\": 1,\n  \"dll_sha256\": \"%s\",\n  \"harness_sha256\": \"%s\",\n"
        "  \"operation\": \"%s\",\n  \"delta_file\": \"delta.pa31\",\n  \"info_output_size\": %llu,\n"
        "  \"native_reverse_created\": %s,\n  \"forward_create_error\": %lu,\n"
        "  \"forward_apply_error\": %lu,\n  \"get_reverse_error\": %lu,\n"
        "  \"forward_delta_sha256\": \"%s\",\n  \"get_reverse_target_sha256\": \"%s\",\n"
        "  \"source_sha256\": \"%s\",\n  \"delta_sha256\": \"%s\",\n  \"target_sha256\": \"%s\",\n"
        "  \"get_info_ok\": %s,\n  \"get_info_error\": %lu,\n  \"apply_ok\": %s,\n"
        "  \"apply_error\": %lu,\n  \"target_equal\": %s,\n  \"applied_sha256\": \"%s\",\n"
        "  \"header_info_sha256\": \"%s\",\n  \"noneditable_inputs_unchanged\": true,\n"
        "  \"info_structure_size\": %u,\n  \"info_format_version\": %u,\n"
        "  \"info_minimum_client_version\": %u,\n  \"info_hash_algorithm\": %u,\n"
        "  \"info_file_type_set\": %llu,\n  \"info_source_hash_size\": %u,\n  \"info_target_hash_size\": %u\n}\n",
        dll_hash, harness_hash, argv[1], (unsigned long long)sizeof header,
        create ? "true" : "false", create_error, forward_error, reverse_error, forward_hash, reverse_forward_hash,
        source_hash, delta_hash, target_hash, info_ok ? "true" : "false", info_error,
        apply_ok ? "true" : "false", apply_error, exact ? "true" : "false", result_hash, header_hash,
        info_ok ? header.structure_size : 0, info_ok ? header.format_version : 0,
        info_ok ? header.minimum_client_version : 0, info_ok ? header.hash_algorithm : 0,
        (unsigned long long)(info_ok ? header.file_type_set : 0),
        info_ok ? header.source_hash_size : 0, info_ok ? header.target_hash_size : 0) < 0 || fclose(meta))
        fail("write observation");
    if (!MoveFileExA(pending, manifest, MOVEFILE_WRITE_THROUGH)) fail("publish observation");
    printf("info=%d error=%lu reverse_apply=%d error=%lu exact=%d\n", info_ok, info_error, apply_ok, apply_error, exact);
    free(first.bytes); free(second.bytes); if (probe) free(expected.bytes);
    FreeLibrary(module);
    return 0;
}

