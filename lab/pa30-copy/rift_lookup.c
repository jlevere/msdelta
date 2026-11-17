// Point-query oracle for the pinned native RiftTable::GetRift implementation.
// x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 rift_lookup.c -lbcrypt -o rift_lookup.exe
// rift_lookup.exe PATH_TO_PINNED_MSDELTA OUTPUT_JSON
#include <windows.h>
#include <bcrypt.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { int64_t source, target; } Entry;
typedef struct {
    uint64_t unused[2];
    uint64_t count, capacity;
    const Entry *entries;
    uint64_t sorted;
} RiftView;
_Static_assert(offsetof(RiftView, count) == 0x10, "pinned count layout");
_Static_assert(offsetof(RiftView, entries) == 0x20, "pinned entries layout");
typedef int64_t (*LookupFn)(const RiftView *, int64_t, int64_t *);

static const char pinned_hash[] = "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb";
enum { LOOKUP_RVA = 0x1c0d0 };

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

static void emit_case(FILE *file, LookupFn lookup, const char *name,
                      const Entry *entries, size_t count, const int64_t *queries,
                      size_t query_count, BOOL last) {
    const RiftView view = {{0, 0}, count, count, entries, 1};
    fprintf(file, "    {\"name\":\"%s\",\"entries\":[", name);
    for (size_t i = 0; i < count; ++i)
        fprintf(file, "%s[\"%" PRId64 "\",\"%" PRId64 "\"]", i ? "," : "", entries[i].source, entries[i].target);
    fprintf(file, "],\"queries\":[");
    for (size_t i = 0; i < query_count; ++i) {
        int64_t last_position = 0;
        int64_t displacement = lookup(&view, queries[i], &last_position);
        fprintf(file, "%s{\"position\":\"%" PRId64 "\",\"displacement\":\"%" PRId64
                      "\",\"last_position\":\"%" PRId64 "\"}",
                i ? "," : "", queries[i], displacement, last_position);
    }
    fprintf(file, "]}%s\n", last ? "" : ",");
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: rift_lookup.exe DLL OUTPUT_JSON\n"); return 1; }
    char hash[65], harness_hash[65], path[MAX_PATH], own_path[MAX_PATH];
    file_hash(argv[1], hash);
    if (strcmp(hash, pinned_hash)) fail("wrong DLL hash");
    DWORD length = GetFullPathNameA(argv[1], MAX_PATH, path, NULL);
    if (!length || length >= MAX_PATH) fail("DLL path");
    length = GetModuleFileNameA(NULL, own_path, MAX_PATH);
    if (!length || length >= MAX_PATH) fail("harness path");
    file_hash(own_path, harness_hash);
    HMODULE module = LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) fail("load DLL");
    BYTE *entry = (BYTE *)module + LOOKUP_RVA;
    const BYTE prefix[] = {0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74};
    if (memcmp(entry, prefix, sizeof prefix)) fail("wrong function prefix");
    LookupFn lookup = (LookupFn)(void *)entry;
    FILE *output = fopen(argv[2], "wb");
    if (!output) fail("open result");
    fprintf(output, "{\n  \"schema\":1,\n  \"dll_sha256\":\"%s\",\n  \"harness_sha256\":\"%s\",\n"
                    "  \"lookup_rva\":%u,\n  \"integer_encoding\":\"signed64 decimal strings\",\n  \"cases\":[\n",
            hash, harness_hash, LOOKUP_RVA);
    const int64_t empty_queries[] = {INT64_MIN, -1, 0, INT64_MAX};
    emit_case(output, lookup, "empty", NULL, 0, empty_queries, 4, FALSE);
    const Entry one[] = {{5, 9}};
    const int64_t one_queries[] = {4, 5, 6};
    emit_case(output, lookup, "single", one, 1, one_queries, 3, FALSE);
    const Entry duplicates[] = {{0, 10}, {5, 20}, {5, 30}, {10, 40}};
    const int64_t duplicate_queries[] = {4, 5, 6, 9, 10};
    emit_case(output, lookup, "duplicate-source", duplicates, 4, duplicate_queries, 5, FALSE);
    const Entry before_first[] = {{10, 20}, {30, 70}};
    const int64_t before_queries[] = {INT64_MIN, -1, 0, 9, 10, 29, 30, INT64_MAX};
    emit_case(output, lookup, "before-first", before_first, 2, before_queries, 8, FALSE);
    const Entry signed_entries[] = {{-20, -5}, {-5, 5}, {0, -1}, {6, 6}};
    const int64_t signed_queries[] = {-21, -20, -6, -5, -1, 0, 1, 6};
    emit_case(output, lookup, "signed-positions", signed_entries, 4, signed_queries, 8, FALSE);
    const Entry wrapping[] = {{0, 0}, {INT64_MAX, INT64_MIN}};
    const int64_t wrap_queries[] = {INT64_MAX - 1, INT64_MAX};
    emit_case(output, lookup, "wrapping-displacement", wrapping, 2, wrap_queries, 2, FALSE);
    const Entry wrapping_single[] = {{INT64_MIN, INT64_MAX}};
    emit_case(output, lookup, "wrapping-single", wrapping_single, 1, empty_queries, 4, TRUE);
    fprintf(output, "  ]\n}\n");
    if (ferror(output) || fclose(output)) fail("write result");
    FreeLibrary(module);
    puts("captured 34 native GetRift queries across 7 tables");
    return 0;
}
