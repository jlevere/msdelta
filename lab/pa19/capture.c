// Owns a minimal non-PE PA19 oracle vector; no internal native hooks.
// Build: x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 -municode capture.c -lbcrypt -o capture.exe
// Run: capture.exe MSPATCHA_DLL MSPATCHC_DLL NEW_OUTPUT_DIRECTORY
// The output directory must not exist. Inputs are regenerated deterministically.
#include <windows.h>
#include <patchapi.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

enum { INPUT_SIZE = 65537, FILE_LIMIT = 4 * 1024 * 1024 };
static const char apply_hash[] = "c301d1cc359708dde08f2d9e2f5d8a39c92e36be3e9d298a16ec18d4c0dd6ec6";
static const char create_hash[] = "e671f5e786b80ac41a270fe6cf88993288ba9a0dab089adee686d550ecb5a92e";
typedef BOOL (WINAPI *CreateFn)(LPCWSTR, LPCWSTR, LPCWSTR, ULONG, PPATCH_OPTION_DATA);
typedef BOOL (WINAPI *ApplyFn)(LPCWSTR, LPCWSTR, LPCWSTR, ULONG);

static void fail(const char *reason) {
    DWORD error = GetLastError();
    fprintf(stderr, "%s; Windows error=%lu (0x%08lx)\n", reason, error, error);
    ExitProcess(2);
}

static void *allocate(size_t n) {
    if (n > FILE_LIMIT) fail("file exceeds oracle limit");
    void *result = malloc(n ? n : 1);
    if (!result) fail("allocation failed");
    return result;
}

static BYTE *load(LPCWSTR path, size_t *size) {
    FILE *file = _wfopen(path, L"rb");
    if (!file || fseek(file, 0, SEEK_END)) fail("open input");
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET)) fail("size input");
    BYTE *result = allocate((size_t)length);
    if (fread(result, 1, (size_t)length, file) != (size_t)length || fclose(file)) fail("read input");
    *size = (size_t)length;
    return result;
}

static void save(LPCWSTR path, const BYTE *data, size_t size) {
    FILE *file = _wfopen(path, L"wb");
    if (!file || fwrite(data, 1, size, file) != size || fclose(file)) fail("write artifact");
}

static void hash(const BYTE *data, size_t size, char result[65]) {
    BCRYPT_ALG_HANDLE algorithm;
    BYTE digest[32];
    if (size > FILE_LIMIT) fail("hash input exceeds oracle limit");
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        fail("SHA256 provider");
    if (BCryptHash(algorithm, NULL, 0, (PUCHAR)data, (ULONG)size, digest, sizeof digest) < 0)
        fail("SHA256 hash");
    BCryptCloseAlgorithmProvider(algorithm, 0);
    for (size_t i = 0; i < sizeof digest; ++i) sprintf(result + 2 * i, "%02x", digest[i]);
}

static void file_hash(LPCWSTR path, char result[65]) {
    size_t size;
    BYTE *data = load(path, &size);
    hash(data, size, result);
    free(data);
}

static HMODULE pinned_dll(LPCWSTR path, const char *expected) {
    char actual[65];
    file_hash(path, actual);
    if (strcmp(actual, expected)) fail("DLL SHA256 differs from pinned reference");
    WCHAR absolute[MAX_PATH];
    DWORD length = GetFullPathNameW(path, MAX_PATH, absolute, NULL);
    if (!length || length >= MAX_PATH) fail("DLL absolute path");
    HMODULE module = LoadLibraryExW(absolute, NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) fail("load pinned DLL");
    length = GetModuleFileNameW(module, absolute, MAX_PATH);
    if (!length || length >= MAX_PATH) fail("loaded module path");
    file_hash(absolute, actual);
    if (strcmp(actual, expected)) fail("loaded module differs from pinned DLL");
    return module;
}

static void output_path(LPCWSTR directory, LPCWSTR name, WCHAR result[MAX_PATH]) {
    int length = swprintf(result, MAX_PATH, L"%ls/%ls", directory, name);
    if (length < 0 || length >= MAX_PATH) fail("output path too long");
}

int wmain(int argc, WCHAR **argv) {
    if (argc != 4) {
        fwprintf(stderr, L"usage: capture.exe MSPATCHA_DLL MSPATCHC_DLL NEW_OUTPUT_DIRECTORY\n");
        return 1;
    }
    HMODULE apply_module = pinned_dll(argv[1], apply_hash);
    HMODULE create_module = pinned_dll(argv[2], create_hash);
    ApplyFn apply = (ApplyFn)(void *)GetProcAddress(apply_module, "ApplyPatchToFileW");
    CreateFn create = (CreateFn)(void *)GetProcAddress(create_module, "CreatePatchFileW");
    if (!apply || !create) fail("required documented export missing");
    if (!CreateDirectoryW(argv[3], NULL)) fail("output directory must be new");

    BYTE *source = allocate(INPUT_SIZE), *target = allocate(INPUT_SIZE), *wrong = allocate(INPUT_SIZE);
    uint32_t state = UINT32_C(0x91d0e7a5);
    for (size_t i = 0; i < INPUT_SIZE; ++i) {
        // Integer-only xorshift stream: identical bytes across hosts and compilers.
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        source[i] = (BYTE)state;
    }
    memcpy(target, source, INPUT_SIZE);
    const size_t edits[] = {31, 32766, 32767, 32768, 32769, 65530, 65536};
    for (size_t i = 0; i < sizeof edits / sizeof edits[0]; ++i) target[edits[i]] ^= (BYTE)(0x41 + i);
    memcpy(wrong, source, INPUT_SIZE);
    wrong[0x1234] ^= 0x80;

    WCHAR source_path[MAX_PATH], target_path[MAX_PATH], wrong_path[MAX_PATH];
    WCHAR patch_path[MAX_PATH], applied_path[MAX_PATH], rejected_path[MAX_PATH], meta_path[MAX_PATH];
    output_path(argv[3], L"base.bin", source_path);
    output_path(argv[3], L"target.bin", target_path);
    output_path(argv[3], L"wrong-base.bin", wrong_path);
    output_path(argv[3], L"native.pa19", patch_path);
    output_path(argv[3], L"applied.bin", applied_path);
    output_path(argv[3], L"rejected.bin", rejected_path);
    output_path(argv[3], L"capture.json", meta_path);
    save(source_path, source, INPUT_SIZE);
    save(target_path, target, INPUT_SIZE);
    save(wrong_path, wrong, INPUT_SIZE);
    const ULONG flags = PATCH_OPTION_USE_LZX_A | PATCH_OPTION_NO_TIMESTAMP;
    if (!create(source_path, target_path, patch_path, flags, NULL)) fail("CreatePatchFileW failed");
    size_t patch_size;
    BYTE *patch = load(patch_path, &patch_size);
    if (patch_size < 4 || memcmp(patch, "PA19", 4)) fail("native output is not PA19");
    // A tiny patch of effectively incompressible data, plus wrong-source rejection,
    // demonstrates source dependence at the API boundary. Internal copy coverage
    // is a separate experiment; no instruction-level coverage is claimed here.
    if (patch_size >= INPUT_SIZE / 8) fail("patch not sufficiently source-dependent for this vector");
    if (!apply(patch_path, source_path, applied_path, 0)) fail("ApplyPatchToFileW failed");
    size_t applied_size;
    BYTE *applied = load(applied_path, &applied_size);
    if (applied_size != INPUT_SIZE || memcmp(applied, target, INPUT_SIZE)) fail("native roundtrip differs from target");
    SetLastError(ERROR_SUCCESS);
    BOOL wrong_accepted = apply(patch_path, wrong_path, rejected_path, 0);
    DWORD wrong_error = GetLastError();
    if (wrong_accepted || wrong_error != ERROR_PATCH_WRONG_FILE) {
        SetLastError(wrong_error);
        fail("same-size wrong source did not report ERROR_PATCH_WRONG_FILE");
    }

    char source_sha[65], target_sha[65], wrong_sha[65], patch_sha[65], applied_sha[65], harness_sha[65];
    hash(source, INPUT_SIZE, source_sha); hash(target, INPUT_SIZE, target_sha);
    hash(wrong, INPUT_SIZE, wrong_sha); hash(patch, patch_size, patch_sha);
    hash(applied, applied_size, applied_sha);
    WCHAR executable[MAX_PATH];
    DWORD executable_length = GetModuleFileNameW(NULL, executable, MAX_PATH);
    if (!executable_length || executable_length >= MAX_PATH) fail("harness path");
    file_hash(executable, harness_sha);
    FILE *metadata = _wfopen(meta_path, L"wb");
    if (!metadata) fail("open metadata");
    if (fprintf(metadata,
        "{\n  \"schema\": 1,\n  \"case\": \"source-dependent-three-chunks\",\n"
        "  \"mspatcha_sha256\": \"%s\",\n  \"mspatchc_sha256\": \"%s\",\n"
        "  \"harness_sha256\": \"%s\",\n  \"source_sha256\": \"%s\",\n"
        "  \"target_sha256\": \"%s\",\n  \"patch_sha256\": \"%s\",\n"
        "  \"applied_sha256\": \"%s\",\n  \"wrong_source_sha256\": \"%s\",\n"
        "  \"source_size\": %u,\n  \"target_size\": %u,\n  \"patch_size\": %llu,\n"
        "  \"create_flags\": %lu,\n  \"apply_flags\": 0,\n"
        "  \"native_roundtrip_equal\": true,\n  \"same_size_wrong_source_rejected\": true,\n"
        "  \"wrong_source_error\": %lu\n}\n",
        apply_hash, create_hash, harness_sha, source_sha, target_sha, patch_sha, applied_sha, wrong_sha,
        INPUT_SIZE, INPUT_SIZE, (unsigned long long)patch_size, flags, wrong_error) < 0 || fclose(metadata))
        fail("write metadata");
    printf("native PA19: %u source bytes -> %llu patch bytes -> %llu target bytes; exact roundtrip; wrong source rejected with 0x%08lx\n",
           INPUT_SIZE, (unsigned long long)patch_size, (unsigned long long)applied_size, wrong_error);
    free(source); free(target); free(wrong); free(patch); free(applied);
    FreeLibrary(create_module); FreeLibrary(apply_module);
    return 0;
}
