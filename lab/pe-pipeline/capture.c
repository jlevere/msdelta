// Selected native PE leaf stages and PA30 copy boundary, for one pinned DLL.
// Build: x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 capture.c -lbcrypt -o capture.exe
// Run: capture.exe DLL SOURCE DELTA_OR_TARGET OUTPUT_DIRECTORY [--create|EXPECTED_SHA256]
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
_Static_assert(sizeof(void *) == 8 && sizeof(DeltaInput) == 24 && sizeof(DeltaOutput) == 16,
               "capture requires Windows x64 delta ABI");

static const char dll_hash[] = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb";
enum {
    LIMIT = 64 * 1024 * 1024, MAX_SUM_CALLS = 64, TRAP_FLAG = 0x100,
    DECOMPRESS_RVA = 0x7b40, SUM_RVA = 0x1ce10,
    // Symbol/disassembly-derived object layout, specific to the pinned DLL.
    COMPONENT_INPUTS = 0x10, COMPONENT_OUTPUTS = 0x18,
    OBJECT_TYPE = 0xc, INT_VALUE = 0x10,
    LIST_COUNT = 0x18, LIST_ELEMENTS = 0x20,
    BUFFER_MEMORY = 0x18, MEMORY_BYTES = 0x20, MEMORY_SIZE = 0x28,
    RIFT_COUNT = 0x10, RIFT_ENTRIES = 0x20, RIFT_ENTRY_SIZE = 16,
};

typedef struct { BYTE *bytes; size_t size; } Blob;
typedef struct {
    BYTE *entry; BYTE original; unsigned instruction_size; unsigned calls;
    const char *name; uint32_t rva; BYTE prefix[5]; BOOL lock_stage;
} Hook;
static Hook sum_hook, decompress_hook, *active_hook, *stepping_hook;
static Hook stages[] = {
    {.name="mark-non-exe", .rva=0x15780, .instruction_size=5, .prefix={0x48,0x89,0x5c,0x24,0x18}},
    {.name="imports", .rva=0x12850, .instruction_size=2, .prefix={0x40,0x53}},
    {.name="exports", .rva=0x14ce0, .instruction_size=5, .prefix={0x48,0x89,0x5c,0x24,0x08}},
    {.name="resources", .rva=0x1e810, .instruction_size=4, .prefix={0x48,0x83,0xec,0x48}},
    {.name="relocations", .rva=0x25a40, .instruction_size=3, .prefix={0x48,0x8b,0xc4}},
    {.name="inferred-i386", .rva=0x12140, .instruction_size=2, .prefix={0x40,0x53}},
    {.name="cli-disasm", .rva=0x15920, .instruction_size=5, .prefix={0x48,0x89,0x5c,0x24,0x18}},
    {.name="cli-metadata", .rva=0x22ce0, .instruction_size=5, .prefix={0x48,0x89,0x4c,0x24,0x08}},
    {.name="jmps-i386", .rva=0x12300, .instruction_size=5, .prefix={0x48,0x89,0x4c,0x24,0x08}},
    {.name="calls-i386", .rva=0x146f0, .instruction_size=5, .prefix={0x48,0x89,0x4c,0x24,0x08}},
    {.name="disasm-amd64", .rva=0x135d0, .instruction_size=2, .prefix={0x41,0x56}},
    {.name="pdata-amd64", .rva=0x128f0, .instruction_size=2, .prefix={0x40,0x55}},
    {.name="lock-source", .rva=0x11d90, .instruction_size=3, .prefix={0x48,0x8b,0xc4}, .lock_stage=TRUE},
};
enum { MAX_STAGES = 64, CAPTURE_BUDGET = 256 * 1024 * 1024 };
typedef struct {
    Hook *hook;
    uintptr_t component, source, marker;
    uint32_t size;
    uint64_t target_base;
    Blob before, after, marker_before, marker_after, rift;
    unsigned enter_order, leave_order;
} StageCapture;
static StageCapture stage_captures[MAX_STAGES], *active_stage;
static size_t stage_count, allocated_total;
static unsigned event_order;
static BYTE *return_site, return_byte;
static DWORD owner;
static uintptr_t active_component, last_sum_output, source_object, target_object, buffer_list;
static uint64_t reference_size, target_size, sum_unique;
static Blob patch_rift, caller_rift, summed_rift, transformed_source, decompressed_target;
static unsigned completed_decompress;

static void fail(const char *reason) {
    fprintf(stderr, "%s (Windows error %lu)\n", reason, GetLastError());
    ExitProcess(2);
}

static void *allocate(size_t n) {
    if (n > LIMIT) fail("capture exceeds size limit");
    if (n > CAPTURE_BUDGET - allocated_total) fail("total capture budget exceeded");
    allocated_total += n;
    void *p = malloc(n ? n : 1);
    if (!p) fail("allocation failed");
    return p;
}

static void read_memory(uintptr_t at, void *out, size_t n) {
    SIZE_T copied;
    if (n && (!ReadProcessMemory(GetCurrentProcess(), (void *)at, out, n, &copied) || copied != n))
        fail("invalid native object layout");
}

static uint64_t u64(uintptr_t at) { uint64_t n; read_memory(at, &n, 8); return n; }
static uint32_t u32(uintptr_t at) { uint32_t n; read_memory(at, &n, 4); return n; }
static Blob snapshot(uintptr_t at, size_t n) {
    Blob result = {allocate(n), n};
    read_memory(at, result.bytes, n);
    return result;
}
static void drop(Blob *blob) { free(blob->bytes); *blob = (Blob){0}; }
static BOOL equal(Blob a, Blob b) {
    return a.size == b.size && (!a.size || !memcmp(a.bytes, b.bytes, a.size));
}
static uintptr_t input(uintptr_t component, size_t index) {
    return u64(u64(component + COMPONENT_INPUTS) + index * 8);
}
static uintptr_t output_object(uintptr_t component, size_t index) {
    return u64(u64(component + COMPONENT_OUTPUTS) + index * 8);
}
static uint64_t integer(uintptr_t object) {
    if (u32(object + OBJECT_TYPE) != 2) fail("expected integer input");
    return u64(object + INT_VALUE);
}
static Blob capture_rift(uintptr_t object) {
    if (u32(object + OBJECT_TYPE) != 10) fail("expected RiftTable input");
    uint64_t count = u64(object + RIFT_COUNT);
    if (count > LIMIT / RIFT_ENTRY_SIZE) fail("rift exceeds capture limit");
    return snapshot(u64(object + RIFT_ENTRIES), (size_t)count * RIFT_ENTRY_SIZE);
}
static Blob capture_buffer(uintptr_t object) {
    if (u32(object + OBJECT_TYPE) != 3) fail("expected BufferObject input");
    uintptr_t memory = u64(object + BUFFER_MEMORY);
    uint64_t n = u64(memory + MEMORY_SIZE);
    if (n > LIMIT) fail("buffer exceeds capture limit");
    return snapshot(u64(memory + MEMORY_BYTES), (size_t)n);
}

static void patch_byte(BYTE *at, BYTE value, BYTE *saved) {
    DWORD old, unused;
    if (!VirtualProtect(at, 1, PAGE_EXECUTE_READWRITE, &old)) fail("protect breakpoint");
    if (saved) *saved = *at;
    *at = value;
    if (!VirtualProtect(at, 1, old, &unused) || !FlushInstructionCache(GetCurrentProcess(), at, 1))
        fail("install breakpoint");
}

static void capture_entry(Hook *hook, uintptr_t component) {
    if (hook == &sum_hook) {
        if (hook->calls > MAX_SUM_CALLS || decompress_hook.calls) fail("unexpected sum invocation");
        drop(&patch_rift); drop(&caller_rift); drop(&summed_rift);
        patch_rift = capture_rift(input(component, 0));
        caller_rift = capture_rift(input(component, 1));
        sum_unique = integer(input(component, 2));
        last_sum_output = 0;
    } else if (hook == &decompress_hook) {
        if (hook->calls != 1 || !last_sum_output) fail("expected one decompressor invocation after sum");
        uintptr_t merged = input(component, 3);
        if (merged != last_sum_output || sum_unique != 0)
            fail("decompressor rift is not the captured non-unique sum output");
        Blob observed = capture_rift(merged);
        if (!equal(observed, summed_rift)) fail("summed rift changed before decompression");
        drop(&observed);
        reference_size = integer(input(component, 4));
        target_size = integer(input(component, 5));
        if (reference_size > LIMIT || target_size > LIMIT) fail("decompressor sizes exceed capture limit");
        buffer_list = input(component, 2);
        if (u32(buffer_list + OBJECT_TYPE) != 6 || u64(buffer_list + LIST_COUNT) != 2)
            fail("expected source and target buffer list");
        uintptr_t elements = u64(buffer_list + LIST_ELEMENTS);
        source_object = u64(elements);
        target_object = u64(elements + 8);
        transformed_source = capture_buffer(source_object);
        if (transformed_source.size != reference_size
            || u64(u64(target_object + BUFFER_MEMORY) + MEMORY_SIZE) != target_size)
            fail("decompressor sizes do not match buffer extents");
    } else {
        if (stage_count == MAX_STAGES) fail("too many selected stages");
        StageCapture *capture = &stage_captures[stage_count++];
        active_stage = capture;
        capture->hook = hook;
        capture->component = component;
        capture->enter_order = event_order++;
        if (hook->lock_stage) {
            uintptr_t pe = input(component, 0);
            uintptr_t helper = u64(pe + 0x20);
            capture->source = u64(helper);
            capture->size = u32(helper + 8);
        } else {
            BYTE mode;
            read_memory(component + 0xb0, &mode, 1);
            if (mode != 1) fail("selected source transform is not in apply mode");
            capture->source = u64(component + 0x60);
            capture->size = u32(component + 0x68);
            capture->marker = u64(component + 0x98);
            capture->target_base = u64(component + 0xb8);
            capture->rift = capture_rift(u64(component + 0x30));
            capture->marker_before = snapshot(capture->marker, capture->size);
        }
        capture->before = snapshot(capture->source, capture->size);
    }
}

static void capture_return(Hook *hook, uintptr_t component) {
    if (hook == &sum_hook) {
        last_sum_output = output_object(component, 0);
        summed_rift = capture_rift(last_sum_output);
    } else if (hook == &decompress_hook) {
        if (output_object(component, 1) != buffer_list || u64(buffer_list + LIST_COUNT) != 2)
            fail("decompressor changed buffer list identity");
        Blob after = capture_buffer(source_object);
        if (!equal(after, transformed_source)) fail("decompressor changed its source bytes");
        drop(&after);
        decompressed_target = capture_buffer(target_object);
        if (decompressed_target.size != target_size) fail("decompressor changed target size");
        completed_decompress++;
    } else {
        StageCapture *capture = active_stage;
        if (!capture || capture->hook != hook || capture->component != component)
            fail("selected stage identity changed");
        if (!hook->lock_stage && (u64(component + 0x60) != capture->source
            || u32(component + 0x68) != capture->size || u64(component + 0x98) != capture->marker))
            fail("selected stage moved source or markers");
        capture->after = snapshot(capture->source, capture->size);
        if (!hook->lock_stage) capture->marker_after = snapshot(capture->marker, capture->size);
        capture->leave_order = event_order++;
        active_stage = NULL;
    }
}

static LONG CALLBACK on_exception(PEXCEPTION_POINTERS exception) {
    CONTEXT *context = exception->ContextRecord;
    DWORD code = exception->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_SINGLE_STEP && stepping_hook) {
        if (GetCurrentThreadId() != owner
            || context->Rip != (DWORD64)(stepping_hook->entry + stepping_hook->instruction_size))
            fail("unexpected entry single-step");
        patch_byte(stepping_hook->entry, 0xcc, NULL);
        stepping_hook = NULL;
        context->EFlags &= ~TRAP_FLAG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    BYTE *at = exception->ExceptionRecord->ExceptionAddress;
    Hook *hook = at == sum_hook.entry ? &sum_hook : at == decompress_hook.entry ? &decompress_hook : NULL;
    for (size_t index = 0; !hook && index < sizeof stages / sizeof stages[0]; index++) {
        if (at == stages[index].entry) hook = &stages[index];
    }
    if (hook) {
        if (GetCurrentThreadId() != owner || active_hook || (context->EFlags & TRAP_FLAG))
            fail("unexpected nested or foreign-thread stage invocation");
        active_hook = hook;
        active_component = context->Rcx;
        hook->calls++;
        capture_entry(hook, active_component);
        return_site = (BYTE *)(uintptr_t)u64(context->Rsp);
        if (return_site == sum_hook.entry || return_site == decompress_hook.entry)
            fail("invalid stage return address");
        patch_byte(return_site, 0xcc, &return_byte);
        patch_byte(hook->entry, hook->original, NULL);
        // Single-step only the pinned first instruction, then re-arm entry.
        // A concurrent call in this one-instruction gap is outside scope.
        stepping_hook = hook;
        context->Rip = (DWORD64)hook->entry;
        context->EFlags |= TRAP_FLAG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (active_hook && at == return_site) {
        if (GetCurrentThreadId() != owner || stepping_hook) fail("unexpected stage return");
        capture_return(active_hook, active_component);
        patch_byte(return_site, return_byte, NULL);
        context->Rip = (DWORD64)return_site;
        active_hook = NULL;
        return_site = NULL;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static Blob load(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) fail("open input");
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET)) fail("size input");
    Blob blob = {allocate((size_t)length), (size_t)length};
    if (fread(blob.bytes, 1, blob.size, file) != blob.size || fclose(file)) fail("read input");
    return blob;
}
static void hash(Blob blob, char result[65]) {
    if (blob.size > LIMIT) fail("hash input exceeds limit");
    BCRYPT_ALG_HANDLE algorithm;
    BYTE digest[32];
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        fail("SHA256 provider");
    if (BCryptHash(algorithm, NULL, 0, blob.bytes, (ULONG)blob.size, digest, 32) < 0)
        fail("SHA256 calculation");
    BCryptCloseAlgorithmProvider(algorithm, 0);
    for (size_t i = 0; i < 32; i++) sprintf(result + 2 * i, "%02x", digest[i]);
}
static void hash_module(HMODULE module, char result[65]) {
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(module, path, MAX_PATH);
    if (!n || n >= MAX_PATH) fail("module file path");
    Blob file = load(path);
    hash(file, result);
    drop(&file);
}
static void path_for(const char *directory, const char *name, char path[MAX_PATH]) {
    int n = snprintf(path, MAX_PATH, "%s/%s", directory, name);
    if (n < 0 || n >= MAX_PATH) fail("output path too long");
}
static FILE *output(const char *directory, const char *name) {
    char path[MAX_PATH];
    path_for(directory, name, path);
    FILE *file = fopen(path, "wb");
    if (!file) fail("open output");
    return file;
}
static void save(const char *directory, const char *name, Blob blob) {
    FILE *file = output(directory, name);
    if (fwrite(blob.bytes, 1, blob.size, file) != blob.size || fclose(file)) fail("write output");
}
static Blob native_output(DeltaOutput result) {
    if (result.size > LIMIT || (result.size && !result.data)) fail("invalid native output extent");
    return (Blob){result.data, result.size};
}

int main(int argc, char **argv) {
    BOOL mint = argc == 6 && !strcmp(argv[5], "--create");
    const char *expected_sha = argc == 6 && !mint ? argv[5] : NULL;
    if ((argc != 5 && argc != 6) || (expected_sha && strlen(expected_sha) != 64)) {
        fprintf(stderr, "usage: capture.exe DLL SOURCE DELTA_OR_TARGET OUTPUT_DIRECTORY [--create|EXPECTED_SHA256]\n");
        return 1;
    }
    DWORD attributes = GetFileAttributesA(argv[4]);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
        fail("output directory must exist");
    char metadata_path[MAX_PATH], pending_path[MAX_PATH];
    path_for(argv[4], "capture.json", metadata_path);
    path_for(argv[4], "capture.json.tmp", pending_path);
    if (!DeleteFileA(metadata_path) && GetLastError() != ERROR_FILE_NOT_FOUND)
        fail("invalidate previous completion marker");
    char observed_hash[65], harness_hash[65];
    Blob dll_file = load(argv[1]);
    hash(dll_file, observed_hash); drop(&dll_file);
    if (strcmp(observed_hash, dll_hash)) fail("DLL hash does not match native layout");
    char absolute[MAX_PATH];
    DWORD n = GetFullPathNameA(argv[1], MAX_PATH, absolute, NULL);
    if (!n || n >= MAX_PATH) fail("DLL path");
    HMODULE module = LoadLibraryExA(absolute, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) fail("load pinned DLL");
    hash_module(module, observed_hash);
    if (strcmp(observed_hash, dll_hash)) fail("loaded DLL hash mismatch");
    hash_module(NULL, harness_hash);
    ApplyFn apply = (ApplyFn)(void *)GetProcAddress(module, "ApplyDeltaB");
    FreeFn release = (FreeFn)(void *)GetProcAddress(module, "DeltaFree");
    if (!apply || !release) fail("missing delta exports");
    Blob source = load(argv[2]), supplied = load(argv[3]), delta = supplied;
    DeltaOutput created = {0}, control = {0}, instrumented = {0};
    DeltaInput source_input = {source.bytes, source.size, FALSE};
    if (mint) {
        CreateFn create = (CreateFn)(void *)GetProcAddress(module, "CreateDeltaB");
        if (!create) fail("missing CreateDeltaB");
        DeltaInput target_input = {supplied.bytes, supplied.size, FALSE}, empty = {0};
        FILETIME timestamp = {0};
        // Compatible legacy delta signature; capture artifacts use SHA256.
        if (!create(0xf, 0, 0, source_input, target_input, empty, empty, empty, &timestamp, 0x8003, &created))
            fail("native CreateDeltaB failed");
        delta = native_output(created);
    }
    DeltaInput delta_input = {delta.bytes, delta.size, FALSE};
    if (!apply(0, source_input, delta_input, &control)) fail("native uninstrumented ApplyDeltaB failed");
    Blob target = native_output(control);
    if (mint && !equal(target, supplied)) fail("native create/apply differs from target");
    hash(target, observed_hash);
    if (expected_sha && strcmp(expected_sha, observed_hash)) {
        fprintf(stderr, "native target SHA256 %s expected %s\n", observed_hash, expected_sha);
        fail("native uninstrumented output differs from expected digest");
    }
    sum_hook = (Hook){.entry=(BYTE *)module + SUM_RVA, .instruction_size=5, .name="sum-rifts"};
    decompress_hook = (Hook){.entry=(BYTE *)module + DECOMPRESS_RVA, .instruction_size=3, .name="decompress"};
    const BYTE sum_prefix[] = {0x48, 0x89, 0x5c, 0x24, 0x08};
    const BYTE decompress_prefix[] = {0x48, 0x8b, 0xc4, 0x57};
    if (memcmp(sum_hook.entry, sum_prefix, sizeof sum_prefix)
        || memcmp(decompress_hook.entry, decompress_prefix, sizeof decompress_prefix))
        fail("unexpected hook entry instructions");
    for (size_t index = 0; index < sizeof stages / sizeof stages[0]; index++) {
        stages[index].entry = (BYTE *)module + stages[index].rva;
        if (memcmp(stages[index].entry, stages[index].prefix, stages[index].instruction_size))
            fail("unexpected selected stage entry instruction");
    }
    owner = GetCurrentThreadId();
    PVOID handler = AddVectoredExceptionHandler(1, on_exception);
    if (!handler) fail("register exception handler");
    patch_byte(sum_hook.entry, 0xcc, &sum_hook.original);
    patch_byte(decompress_hook.entry, 0xcc, &decompress_hook.original);
    for (size_t index = 0; index < sizeof stages / sizeof stages[0]; index++)
        patch_byte(stages[index].entry, 0xcc, &stages[index].original);
    if (!apply(0, source_input, delta_input, &instrumented)) fail("instrumented ApplyDeltaB failed");
    patch_byte(sum_hook.entry, sum_hook.original, NULL);
    patch_byte(decompress_hook.entry, decompress_hook.original, NULL);
    for (size_t index = 0; index < sizeof stages / sizeof stages[0]; index++)
        patch_byte(stages[index].entry, stages[index].original, NULL);
    if (!RemoveVectoredExceptionHandler(handler)) fail("remove exception handler");
    if (active_hook || stepping_hook || completed_decompress != 1 || decompress_hook.calls != 1)
        fail("incomplete decompressor observation");
    if (!equal(target, native_output(instrumented))) fail("instrumentation changed final output");

    FILE *trace = output(argv[4], "stages.json");
    if (fprintf(trace, "{\n  \"schema\": 1,\n  \"dll_sha256\": \"%s\",\n  \"harness_sha256\": \"%s\",\n"
        "  \"scope\": \"selected leaf transforms and LockSourceBuffer; wrappers are not hooked\",\n  \"stages\": [\n",
        dll_hash, harness_hash) < 0) fail("write stage trace");
    for (size_t index = 0; index < stage_count; index++) {
        StageCapture *stage = &stage_captures[index];
        if (fprintf(trace, "    {\"id\": %llu, \"name\": \"%s\", \"rva\": %u, \"enter_order\": %u, \"leave_order\": %u, "
            "\"source_size\": %u, \"target_base\": %llu, \"has_markers\": %s, \"artifact_sha256\": {",
            (unsigned long long)index, stage->hook->name, stage->hook->rva, stage->enter_order, stage->leave_order,
            stage->size, (unsigned long long)stage->target_base, stage->hook->lock_stage ? "false" : "true") < 0)
            fail("write stage record");
        struct { const char *suffix; Blob blob; } blobs[] = {
            {"before",stage->before},{"after",stage->after},{"marker-before",stage->marker_before},
            {"marker-after",stage->marker_after},{"rift",stage->rift},
        };
        for (size_t field = 0; field < sizeof blobs / sizeof blobs[0]; field++) {
            char name[128], digest[65];
            snprintf(name, sizeof name, "stage-%02llu-%s-%s.bin", (unsigned long long)index, stage->hook->name, blobs[field].suffix);
            save(argv[4], name, blobs[field].blob); hash(blobs[field].blob, digest);
            if (fprintf(trace, "%s\"%s\":\"%s\"", field ? "," : "", name, digest) < 0) fail("write stage digest");
        }
        if (fprintf(trace, "}}%s\n", index + 1 == stage_count ? "" : ",") < 0) fail("write stage record terminator");
    }
    if (fprintf(trace, "  ]\n}\n") < 0 || fclose(trace)) fail("finish stage trace");
    char trace_path[MAX_PATH], trace_hash[65];
    path_for(argv[4], "stages.json", trace_path);
    Blob trace_bytes = load(trace_path); hash(trace_bytes, trace_hash); drop(&trace_bytes);

    struct Artifact { const char *name; Blob blob; } artifacts[] = {
        {"source.bin", source}, {"delta.pa30", delta}, {"target.bin", target},
        {"transformed-source.bin", transformed_source}, {"decompressed-target.bin", decompressed_target},
        {"caller-rift.bin", caller_rift}, {"patch-rift.bin", patch_rift}, {"merged-rift.bin", summed_rift},
    };
    size_t artifact_count = sizeof artifacts / sizeof artifacts[0];
    char artifact_hashes[sizeof artifacts / sizeof artifacts[0]][65];
    for (size_t index = 0; index < artifact_count; index++) {
        save(argv[4], artifacts[index].name, artifacts[index].blob);
        hash(artifacts[index].blob, artifact_hashes[index]);
    }
    if (!release(control.data) || !release(instrumented.data) || (mint && !release(created.data)))
        fail("native output release failed");
    FILE *meta = output(argv[4], "capture.json.tmp");
    if (fprintf(meta,
        "{\n  \"schema\": 1,\n  \"dll_sha256\": \"%s\",\n  \"harness_sha256\": \"%s\",\n"
        "  \"stage_trace_sha256\": \"%s\",\n  \"stage_count\": %llu,\n"
        "  \"decompress_rva\": %u,\n  \"sum_rva\": %u,\n  \"sum_calls\": %u,\n"
        "  \"reference_size\": %llu,\n  \"target_size\": %llu,\n  \"original_source_size\": %llu,\n"
        "  \"folded\": true,\n  \"rift_encoding\": \"signed64-le source,target pairs\",\n"
        "  \"caller_rift_domain\": \"reference_size + target file offset -> source file offset\",\n"
        "  \"patch_rift_origin\": \"SumRiftTables input 0, decoded patch-local rift\",\n"
        "  \"caller_rift_origin\": \"SumRiftTables input 1, apply-preprocess copy map after reference-size composition and reduction\",\n"
        "  \"merged_rift_origin\": \"SumRiftTables output 0, identity matched to Decompress input 3\",\n"
        "  \"observation_scope\": \"synchronous caller thread\",\n"
        "  \"uninstrumented_output_equal\": true,\n  \"decompress_source_unchanged\": true,\n"
        "  \"artifact_sha256\": {\n",
        dll_hash, harness_hash, trace_hash, (unsigned long long)stage_count, DECOMPRESS_RVA, SUM_RVA, sum_hook.calls,
        (unsigned long long)reference_size, (unsigned long long)target_size,
        (unsigned long long)source.size) < 0) fail("write capture metadata");
    for (size_t index = 0; index < artifact_count; index++) {
        if (fprintf(meta, "    \"%s\": \"%s\"%s\n", artifacts[index].name, artifact_hashes[index],
                    index + 1 == artifact_count ? "" : ",") < 0) fail("write artifact hashes");
    }
    if (fprintf(meta, "  }\n}\n") < 0 || fclose(meta)) fail("finish capture metadata");
    if (!MoveFileExA(pending_path, metadata_path, MOVEFILE_WRITE_THROUGH)) fail("publish capture metadata");
    printf("captured source=%llu target=%llu caller=%llu patch=%llu merged=%llu; native control identical\n",
        (unsigned long long)reference_size, (unsigned long long)target_size,
        (unsigned long long)(caller_rift.size / RIFT_ENTRY_SIZE),
        (unsigned long long)(patch_rift.size / RIFT_ENTRY_SIZE),
        (unsigned long long)(summed_rift.size / RIFT_ENTRY_SIZE));
    drop(&source); drop(&supplied); drop(&patch_rift); drop(&caller_rift);
    drop(&summed_rift); drop(&transformed_source); drop(&decompressed_target);
    for (size_t index = 0; index < stage_count; index++) {
        StageCapture *stage = &stage_captures[index];
        drop(&stage->before); drop(&stage->after); drop(&stage->marker_before); drop(&stage->marker_after); drop(&stage->rift);
    }
    FreeLibrary(module);
    return 0;
}
