// Native stage oracle for the pinned msdelta build. Build on macOS with:
// x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 capture.c -lbcrypt -o capture.exe
// Run in an isolated Windows process:
// capture.exe DLL SOURCE DELTA_OR_TARGET OUTPUT_DIRECTORY [--create]
// The directory must exist. No background workers or injected dependencies.
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const void *data; SIZE_T size; BOOL editable; } DeltaInput;
typedef struct { void *data; SIZE_T size; } DeltaOutput;
typedef BOOL (WINAPI *ApplyFn)(int64_t, DeltaInput, DeltaInput, DeltaOutput *);
typedef BOOL (WINAPI *FreeFn)(void *);
typedef BOOL (WINAPI *CreateFn)(int64_t, int64_t, int64_t, DeltaInput, DeltaInput,
                              DeltaInput, DeltaInput, DeltaInput, FILETIME *, ULONG, DeltaOutput *);

static const char dll_hash[] = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb";
enum { TRANSFORM_RVA = 0x25a40, LIMIT = 64 * 1024 * 1024 };
// Private object layout from the symbols/disassembly of the hash-pinned DLL.
// These offsets belong to instrumentation only, never the file-format parser.
enum {
    COMPONENT_RIFT = 0x30,
    COMPONENT_SOURCE = 0x60,
    COMPONENT_SOURCE_SIZE = 0x68,
    COMPONENT_DIRECTORIES = 0x78,
    COMPONENT_MARKERS = 0x98,
    COMPONENT_RIFT_USAGE = 0xa0,
    COMPONENT_RIFT_USAGE_COUNT = 0xa8,
    COMPONENT_APPLY_MODE = 0xb0,
    COMPONENT_TARGET_BASE = 0xb8,
    RIFT_COUNT = 0x10,
    RIFT_ENTRIES = 0x20,
    RELOC_DIRECTORY = 0x140,
    RELOC_DIRECTORY_SIZE = 0x148,
    RELOC_DIRECTORY_CAPACITY = 0x14c,
    RIFT_ENTRY_SIZE = 16,
    ENTRY_INSTRUCTION_SIZE = 3,
    TRAP_FLAG = 0x100,
};
_Static_assert(sizeof(void *) == 8, "capture requires the Windows x64 ABI");
_Static_assert(sizeof(DeltaInput) == 24, "unexpected DELTA_INPUT ABI");
_Static_assert(sizeof(DeltaOutput) == 16, "unexpected DELTA_OUTPUT ABI");
static BYTE *entry, *return_site, entry_byte, return_byte;
static uintptr_t component, buffer, markers, used;
static uint32_t size, directory_size, directory_capacity;
static uint64_t target_base, rift_count, used_count, directory_offset;
static BYTE *before, *after, *marker_before, *marker_after;
static BYTE *rift_entries, *used_before, *used_after;
static DWORD owner;
static unsigned entered, returned;
static BOOL stepping_entry;

static void fail(const char *reason) {
    fprintf(stderr, "%s (Windows error %lu)\n", reason, GetLastError());
    ExitProcess(2);
}

static void *allocate(size_t n) {
    if (n > LIMIT) fail("capture exceeds size limit");
    void *p = malloc(n ? n : 1);
    if (!p) fail("allocation failed");
    return p;
}

static void read_memory(uintptr_t address, void *out, size_t n) {
    SIZE_T copied = 0;
    if (n && (!ReadProcessMemory(GetCurrentProcess(), (void *)address, out, n, &copied)
              || copied != n)) fail("invalid native object layout");
}

static uint64_t u64(uintptr_t at) { uint64_t v; read_memory(at, &v, 8); return v; }
static uint32_t u32(uintptr_t at) { uint32_t v; read_memory(at, &v, 4); return v; }

static BYTE *snapshot(uintptr_t at, size_t n) {
    BYTE *p = allocate(n);
    read_memory(at, p, n);
    return p;
}

static void patch_byte(BYTE *at, BYTE value, BYTE *saved) {
    DWORD old, unused;
    if (!VirtualProtect(at, 1, PAGE_EXECUTE_READWRITE, &old)) fail("protect breakpoint");
    if (saved) *saved = *at;
    *at = value;
    if (!VirtualProtect(at, 1, old, &unused)
        || !FlushInstructionCache(GetCurrentProcess(), at, 1)) fail("install breakpoint");
}

static LONG CALLBACK on_exception(PEXCEPTION_POINTERS exception) {
    CONTEXT *context = exception->ContextRecord;
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP && stepping_entry) {
        if (GetCurrentThreadId() != owner || context->Rip != (DWORD64)(entry + ENTRY_INSTRUCTION_SIZE))
            fail("unexpected entry single-step");
        patch_byte(entry, 0xcc, NULL);
        stepping_entry = FALSE;
        context->EFlags &= ~TRAP_FLAG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (exception->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;
    BYTE *at = exception->ExceptionRecord->ExceptionAddress;
    if (at == entry) {
        if (GetCurrentThreadId() != owner) fail("stage executed on a different thread");
        if (entered++) fail("multiple relocation stage invocations");
        if (context->EFlags & TRAP_FLAG) fail("capture cannot run under an active single-step debugger");
        component = context->Rcx;
        BYTE apply_mode;
        read_memory(component + COMPONENT_APPLY_MODE, &apply_mode, 1);
        if (apply_mode != 1) fail("expected apply mode");
        buffer = u64(component + COMPONENT_SOURCE);
        size = u32(component + COMPONENT_SOURCE_SIZE);
        markers = u64(component + COMPONENT_MARKERS);
        target_base = u64(component + COMPONENT_TARGET_BASE);
        uintptr_t rift = u64(component + COMPONENT_RIFT);
        rift_count = u64(rift + RIFT_COUNT);
        if (rift_count > LIMIT / RIFT_ENTRY_SIZE) fail("invalid rift count");
        rift_entries = snapshot(u64(rift + RIFT_ENTRIES), (size_t)rift_count * RIFT_ENTRY_SIZE);
        uintptr_t directories = u64(component + COMPONENT_DIRECTORIES);
        uintptr_t directory = u64(directories + RELOC_DIRECTORY);
        directory_size = u32(directories + RELOC_DIRECTORY_SIZE);
        directory_capacity = u32(directories + RELOC_DIRECTORY_CAPACITY);
        if (directory < buffer || directory - buffer > size
            || directory_size > size - (directory - buffer)
            || directory_capacity > size - (directory - buffer)) fail("invalid relocation extent");
        directory_offset = directory - buffer;
        used = u64(component + COMPONENT_RIFT_USAGE);
        used_count = used ? u64(component + COMPONENT_RIFT_USAGE_COUNT) : 0;
        before = snapshot(buffer, size);
        marker_before = snapshot(markers, size);
        used_before = snapshot(used, (size_t)used_count);
        after = allocate(size);
        marker_after = allocate(size);
        used_after = allocate((size_t)used_count);
        return_site = (BYTE *)(uintptr_t)u64(context->Rsp);
        if (return_site == entry) fail("invalid return site");
        patch_byte(entry, entry_byte, NULL);
        patch_byte(return_site, 0xcc, &return_byte);
        context->Rip = (DWORD64)entry;
        // Re-arm after the first instruction, not after the entire call, so
        // synchronous recursion is observed. Concurrent calls during this
        // one-instruction window are outside this single-thread oracle's scope.
        stepping_entry = TRUE;
        context->EFlags |= TRAP_FLAG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (at == return_site) {
        if (GetCurrentThreadId() != owner || returned++) fail("unexpected stage return");
        if (stepping_entry) fail("stage returned before its entry instruction");
        if (u64(component + COMPONENT_SOURCE) != buffer || u64(component + COMPONENT_MARKERS) != markers
            || u32(component + COMPONENT_SOURCE_SIZE) != size
            || u64(component + COMPONENT_RIFT_USAGE) != used
            || (used && u64(component + COMPONENT_RIFT_USAGE_COUNT) != used_count))
            fail("stage buffer identity changed");
        read_memory(buffer, after, size);
        read_memory(markers, marker_after, size);
        read_memory(used, used_after, (size_t)used_count);
        patch_byte(return_site, return_byte, NULL);
        context->Rip = (DWORD64)return_site;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BYTE *load(const char *path, size_t *size_out) {
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) fail("open input");
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET)) fail("size input");
    BYTE *bytes = allocate((size_t)length);
    if (fread(bytes, 1, (size_t)length, file) != (size_t)length || fclose(file)) fail("read input");
    *size_out = (size_t)length;
    return bytes;
}

static void hash(const BYTE *bytes, size_t n, char result[65]) {
    if (n > LIMIT) fail("hash input exceeds capture size limit");
    BCRYPT_ALG_HANDLE algorithm;
    BYTE digest[32];
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        fail("SHA256 provider");
    if (BCryptHash(algorithm, NULL, 0, (PUCHAR)bytes, (ULONG)n, digest, 32) < 0)
        fail("SHA256 calculation");
    BCryptCloseAlgorithmProvider(algorithm, 0);
    for (size_t i = 0; i < 32; i++) sprintf(result + 2 * i, "%02x", digest[i]);
}

static void output_path(const char *directory, const char *name, char path[MAX_PATH]) {
    int n = snprintf(path, MAX_PATH, "%s/%s", directory, name);
    if (n < 0 || n >= MAX_PATH) fail("output path too long");
}

static FILE *output(const char *directory, const char *name) {
    char path[MAX_PATH];
    output_path(directory, name, path);
    FILE *file = fopen(path, "wb");
    if (!file) fail("open output");
    return file;
}

static void hash_module_file(HMODULE module, char result[65]) {
    char path[MAX_PATH];
    DWORD length = GetModuleFileNameA(module, path, MAX_PATH);
    if (!length || length >= MAX_PATH) fail("module file path");
    size_t n;
    BYTE *bytes = load(path, &n);
    hash(bytes, n, result);
    free(bytes);
}

static void validate_output(DeltaOutput result) {
    if (result.size > LIMIT || (result.size && !result.data)) fail("invalid native output extent");
}

static void save(const char *directory, const char *name, const void *bytes, size_t n) {
    FILE *file = output(directory, name);
    if (fwrite(bytes, 1, n, file) != n || fclose(file)) fail("write output");
}

int main(int argc, char **argv) {
    BOOL mint = argc == 6 && !strcmp(argv[5], "--create");
    if (argc != 5 && !mint) { fprintf(stderr, "usage: capture.exe DLL SOURCE DELTA_OR_TARGET OUTPUT_DIRECTORY [--create]\n"); return 1; }
    DWORD attributes = GetFileAttributesA(argv[4]);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
        fail("output directory must exist");
    // The manifest is the completion marker. A failed regeneration must not
    // leave an older manifest describing partially replaced artifacts.
    char metadata_path[MAX_PATH], pending_metadata_path[MAX_PATH];
    output_path(argv[4], "capture.json", metadata_path);
    output_path(argv[4], "capture.json.tmp", pending_metadata_path);
    if (!DeleteFileA(metadata_path) && GetLastError() != ERROR_FILE_NOT_FOUND)
        fail("invalidate previous capture manifest");
    size_t dll_size, source_size, delta_size;
    BYTE *dll_bytes = load(argv[1], &dll_size);
    char actual_hash[65], source_hash[65], delta_hash[65], target_hash[65], harness_hash[65];
    hash(dll_bytes, dll_size, actual_hash);
    free(dll_bytes);
    if (strcmp(actual_hash, dll_hash)) fail("DLL SHA256 does not match the symbol layout");
    char absolute[MAX_PATH];
    DWORD path_size = GetFullPathNameA(argv[1], MAX_PATH, absolute, NULL);
    if (!path_size || path_size >= MAX_PATH) fail("DLL path");
    HMODULE module = LoadLibraryExA(absolute, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) fail("load pinned DLL");
    // Also identify the module the loader actually selected, rather than only
    // hashing the requested path before resolution.
    hash_module_file(module, actual_hash);
    if (strcmp(actual_hash, dll_hash)) fail("loaded DLL does not match the symbol layout");
    hash_module_file(NULL, harness_hash);
    ApplyFn apply = (ApplyFn)(void *)GetProcAddress(module, "ApplyDeltaB");
    FreeFn release = (FreeFn)(void *)GetProcAddress(module, "DeltaFree");
    if (!apply || !release) fail("missing delta exports");
    BYTE *source_bytes = load(argv[2], &source_size), *delta_bytes = load(argv[3], &delta_size);
    DeltaOutput created = {0};
    BYTE *expected_target = NULL;
    size_t expected_size = 0;
    if (mint) {
        CreateFn create = (CreateFn)(void *)GetProcAddress(module, "CreateDeltaB");
        if (!create) fail("missing CreateDeltaB");
        DeltaInput s = {source_bytes, source_size, FALSE}, t = {delta_bytes, delta_size, FALSE}, empty = {0};
        FILETIME timestamp = {0};
        // This build uses the legacy CryptoAPI provider for delta signatures.
        // MD5 is a format compatibility choice; capture provenance uses SHA256.
        if (!create(0xf, 0, 0, s, t, empty, empty, empty, &timestamp, 0x8003, &created))
            fail("CreateDeltaB failed");
        validate_output(created);
        expected_target = delta_bytes;
        expected_size = delta_size;
        delta_bytes = created.data;
        delta_size = created.size;
        save(argv[4], "native.pa30", delta_bytes, delta_size);
    }
    hash(source_bytes, source_size, source_hash);
    hash(delta_bytes, delta_size, delta_hash);
    DeltaInput source = {source_bytes, source_size, FALSE}, delta = {delta_bytes, delta_size, FALSE};
    DeltaOutput control = {0}, instrumented = {0};
    if (!apply(0, source, delta, &control)) fail("uninstrumented ApplyDeltaB failed");
    validate_output(control);
    if (mint && (control.size != expected_size || memcmp(control.data, expected_target, expected_size)))
        fail("native create/apply roundtrip differs from target");
    entry = (BYTE *)module + TRANSFORM_RVA;
    const BYTE prefix[] = {0x48, 0x8b, 0xc4, 0x57, 0x41, 0x54};
    if (memcmp(entry, prefix, sizeof prefix)) fail("unexpected relocation entry bytes");
    owner = GetCurrentThreadId();
    PVOID handler = AddVectoredExceptionHandler(1, on_exception);
    if (!handler) fail("register handler");
    patch_byte(entry, 0xcc, &entry_byte);
    if (!apply(0, source, delta, &instrumented)) fail("instrumented ApplyDeltaB failed");
    validate_output(instrumented);
    patch_byte(entry, entry_byte, NULL);
    if (!RemoveVectoredExceptionHandler(handler)) fail("remove handler");
    if (entered != 1 || returned != 1 || stepping_entry) fail("relocation stage was not captured exactly once");
    if (control.size != instrumented.size || memcmp(control.data, instrumented.data, control.size))
        fail("instrumentation changed ApplyDeltaB output");
    hash(control.data, control.size, target_hash);
    save(argv[4], "before.bin", before, size);
    save(argv[4], "after.bin", after, size);
    save(argv[4], "marker-before.bin", marker_before, size);
    save(argv[4], "marker-after.bin", marker_after, size);
    save(argv[4], "rift.bin", rift_entries, (size_t)rift_count * RIFT_ENTRY_SIZE);
    save(argv[4], "used-before.bin", used_before, (size_t)used_count);
    save(argv[4], "used-after.bin", used_after, (size_t)used_count);
    if (!release(control.data) || !release(instrumented.data)) fail("DeltaFree failed");
    if (mint && !release(created.data)) fail("created delta release failed");
    FILE *meta = output(argv[4], "capture.json.tmp");
    if (fprintf(meta,
        "{\n  \"schema\": 1,\n  \"dll_sha256\": \"%s\",\n  \"transform_rva\": %u,\n"
        "  \"harness_sha256\": \"%s\",\n  \"delta_origin\": \"%s\",\n"
        "  \"observation_scope\": \"synchronous caller thread\",\n"
        "  \"source_sha256\": \"%s\",\n  \"delta_sha256\": \"%s\",\n  \"target_sha256\": \"%s\",\n"
        "  \"target_base\": %llu,\n  \"directory_offset\": %llu,\n  \"directory_size\": %u,\n"
        "  \"directory_capacity\": %u,\n  \"rift_count\": %llu,\n  \"used_count\": %llu,\n"
        "  \"uninstrumented_output_equal\": true,\n  \"artifact_sha256\": {\n",
        dll_hash, TRANSFORM_RVA, harness_hash, mint ? "native CreateDeltaB" : "supplied delta",
        source_hash, delta_hash, target_hash,
        (unsigned long long)target_base, (unsigned long long)directory_offset,
        directory_size, directory_capacity, (unsigned long long)rift_count,
        (unsigned long long)used_count) < 0) fail("write metadata");
    struct Artifact { const char *name; const BYTE *bytes; size_t length; } artifacts[] = {
        {"before.bin", before, size}, {"after.bin", after, size},
        {"marker-before.bin", marker_before, size}, {"marker-after.bin", marker_after, size},
        {"rift.bin", rift_entries, (size_t)rift_count * RIFT_ENTRY_SIZE},
        {"used-before.bin", used_before, (size_t)used_count}, {"used-after.bin", used_after, (size_t)used_count},
    };
    size_t artifact_count = sizeof artifacts / sizeof artifacts[0];
    for (size_t index = 0; index < artifact_count; index++) {
        char digest[65];
        hash(artifacts[index].bytes, artifacts[index].length, digest);
        if (fprintf(meta, "    \"%s\": \"%s\"%s\n", artifacts[index].name, digest,
                    index + 1 == artifact_count ? "" : ",") < 0) fail("write artifact hash");
    }
    if (fprintf(meta, "  }\n}\n") < 0 || fclose(meta)) fail("finish metadata");
    if (!MoveFileExA(pending_metadata_path, metadata_path, MOVEFILE_WRITE_THROUGH))
        fail("publish capture manifest");
    printf("captured %u source bytes, %llu rift entries; native control output identical\n",
           size, (unsigned long long)rift_count);
    free(source_bytes);
    if (mint) { free(expected_target); } else { free(delta_bytes); }
    free(before); free(after); free(marker_before); free(marker_after);
    free(rift_entries); free(used_before); free(used_after);
    FreeLibrary(module);
    return 0;
}
