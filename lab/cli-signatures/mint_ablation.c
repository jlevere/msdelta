// Export-only owned ablation: native CreateDeltaB with the CLI metadata flag reset.
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { const void *data; SIZE_T size; BOOL editable; } DeltaInput;
typedef struct { void *data; SIZE_T size; } DeltaOutput;
typedef struct { BYTE *bytes; size_t size; } Blob;
typedef BOOL (WINAPI *CreateFn)(int64_t, int64_t, int64_t, DeltaInput, DeltaInput,
                              DeltaInput, DeltaInput, DeltaInput, FILETIME *, ULONG, DeltaOutput *);
typedef BOOL (WINAPI *ApplyFn)(int64_t, DeltaInput, DeltaInput, DeltaOutput *);
typedef BOOL (WINAPI *FreeFn)(void *);
_Static_assert(sizeof(void *) == 8 && sizeof(DeltaInput) == 24 && sizeof(DeltaOutput) == 16,
               "Windows x64 delta ABI required");
static const char dll_hash[] = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb";
enum { LIMIT = 16 * 1024 * 1024 };
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
    if (argc != 6 || (strcmp(argv[1], "normal") && strcmp(argv[1], "no-metadata"))) {
        fprintf(stderr, "usage: mint.exe normal|no-metadata DLL SOURCE TARGET OUTPUT_DIRECTORY\n");
        return 1;
    }
    const char *directory = argv[5];
    DWORD attributes = GetFileAttributesA(directory);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) fail("output directory");
    char manifest[MAX_PATH], pending[MAX_PATH];
    output_path(directory, "creation.json", manifest); output_path(directory, "creation.json.tmp", pending);
    if (GetFileAttributesA(manifest) != INVALID_FILE_ATTRIBUTES) fail("preserve previous completed ablation");
    char observed[65], harness[65], source_hash[65], target_hash[65], delta_hash[65];
    Blob dll = load(argv[2]); hash(dll, observed); free(dll.bytes);
    if (strcmp(observed, dll_hash)) fail("DLL hash mismatch");
    char absolute[MAX_PATH];
    DWORD n = GetFullPathNameA(argv[2], MAX_PATH, absolute, NULL);
    if (!n || n >= MAX_PATH) fail("DLL path");
    HMODULE module = LoadLibraryExA(absolute, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) fail("load pinned DLL");
    hash_module(module, observed); if (strcmp(observed, dll_hash)) fail("loaded DLL mismatch");
    hash_module(NULL, harness);
    CreateFn create = (CreateFn)(void *)GetProcAddress(module, "CreateDeltaB");
    ApplyFn apply = (ApplyFn)(void *)GetProcAddress(module, "ApplyDeltaB");
    FreeFn release = (FreeFn)(void *)GetProcAddress(module, "DeltaFree");
    if (!create || !apply || !release) fail("required exports");
    Blob source = load(argv[3]), target = load(argv[4]);
    hash(source, source_hash); hash(target, target_hash);
    DeltaInput source_input = {source.bytes, source.size, FALSE}, target_input = {target.bytes, target.size, FALSE}, empty = {0};
    DeltaOutput created = {0}, applied = {0}; FILETIME timestamp = {0};
    int64_t reset = strcmp(argv[1], "normal") ? 0x8000 : 0;
    SetLastError(0);
    BOOL create_ok = create(0xf, 0, reset, source_input, target_input, empty, empty, empty, &timestamp, 0x8003, &created);
    DWORD create_error = GetLastError();
    if (!create_ok) fail("native CreateDeltaB ablation rejected");
    Blob delta = native_output(created); hash(delta, delta_hash);
    DeltaInput delta_input = {delta.bytes, delta.size, FALSE};
    SetLastError(0); BOOL apply_ok = apply(0, source_input, delta_input, &applied); DWORD apply_error = GetLastError();
    if (!apply_ok) fail("native ablation ApplyDeltaB rejected");
    Blob actual = native_output(applied);
    if (actual.size != target.size || memcmp(actual.bytes, target.bytes, target.size)) fail("native ablation target differs");
    hash(source, observed); if (strcmp(observed, source_hash)) fail("source changed");
    hash(target, observed); if (strcmp(observed, target_hash)) fail("target changed");
    hash(delta, observed); if (strcmp(observed, delta_hash)) fail("delta changed");
    save(directory, "source.bin", source); save(directory, "target.bin", target); save(directory, "delta.pa30", delta);
    FILE *file = output(directory, "creation.json.tmp");
    if (fprintf(file, "{\n  \"schema\":1,\"mode\":\"%s\",\"reset_flags\":%lld,\n  \"dll_sha256\":\"%s\",\"harness_sha256\":\"%s\",\n  \"create_ok\":true,\"create_error\":%lu,\"apply_ok\":true,\"apply_error\":%lu,\n  \"output_equal\":true,\"inputs_unchanged\":true,\n  \"source_sha256\":\"%s\",\"target_sha256\":\"%s\",\"delta_sha256\":\"%s\"\n}\n", argv[1], (long long)reset, dll_hash, harness, create_error, apply_error, source_hash, target_hash, delta_hash) < 0 || fclose(file)) fail("write creation provenance");
    if (!release(created.data) || !release(applied.data)) fail("release native outputs");
    if (!MoveFileExA(pending, manifest, MOVEFILE_WRITE_THROUGH)) fail("publish creation provenance");
    free(source.bytes); free(target.bytes); FreeLibrary(module);
    return 0;
}
