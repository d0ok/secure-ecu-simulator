#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "counter_store.h"

static int g_run, g_failed;
#define CHECK(name, cond) do { g_run++; \
    if (cond) { printf("[PASS] %s\n", name); } \
    else { g_failed++; printf("[FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        (void)fputs(content, f);
        (void)fclose(f);
    }
}

static void read_file(const char *path, char *out, size_t len)
{
    FILE *f = fopen(path, "r");
    size_t n = 0;
    if (f != NULL) {
        n = fread(out, 1, len - 1U, f);
        (void)fclose(f);
    }
    out[n] = '\0';
}

int main(void)
{
    char dir[] = "/tmp/cstore_test_XXXXXX";
    char path[256], tmp[260], content[128], buf[CSTORE_PATH_MAX];
    struct stat st;
    uint32_t v = 0;
    size_t i;

    static const struct { const char *name; const char *content; } bad[] = {
        { "reject garbage text",              "garbage\n" },
        { "reject empty file",                "" },
        { "reject truncated record",          "v1 5\n" },
        { "reject wrong complement",          "v1 5 fffffffb\n" },
        { "reject negative value",            "v1 -5 5\n" },
        { "reject extra second line",         "v1 5 fffffffa\nv1 6 fffffff9\n" },
        { "reject value above 32 bits",       "v1 4294967296 0\n" },
        { "reject missing separator",         "v15 fffffffa\n" },
        { "reject trailing text",             "v1 5 fffffffa junk\n" }
    };

    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/counter", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    CHECK("missing file reports NOT_FOUND", cstore_load(path, &v) == CSTORE_NOT_FOUND);

    CHECK("save 42", cstore_save(path, 42U) == CSTORE_OK);
    CHECK("load returns saved value", cstore_load(path, &v) == CSTORE_OK && v == 42U);
    read_file(path, content, sizeof(content));
    CHECK("file format is v1 <counter> <complement>", strcmp(content, "v1 42 ffffffd5\n") == 0);
    CHECK("file mode is 0600", stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK("no temp file left behind", access(tmp, F_OK) != 0);

    CHECK("overwrite with a larger value", cstore_save(path, 1000U) == CSTORE_OK);
    CHECK("load sees the newest value", cstore_load(path, &v) == CSTORE_OK && v == 1000U);
    CHECK("round trip 0", cstore_save(path, 0U) == CSTORE_OK
                          && cstore_load(path, &v) == CSTORE_OK && v == 0U);
    CHECK("round trip UINT32_MAX", cstore_save(path, UINT32_MAX) == CSTORE_OK
                                   && cstore_load(path, &v) == CSTORE_OK && v == UINT32_MAX);

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        write_file(path, bad[i].content);
        CHECK(bad[i].name, cstore_load(path, &v) == CSTORE_CORRUPT);
    }

    CHECK("unwritable location reports IO_ERROR",
          cstore_save("/nonexistent_cstore_dir/counter", 1U) == CSTORE_IO_ERROR);
    CHECK("NULL path rejected on save", cstore_save(NULL, 1U) == CSTORE_BAD_ARG);
    CHECK("NULL path rejected on load", cstore_load(NULL, &v) == CSTORE_BAD_ARG);
    CHECK("NULL output rejected on load", cstore_load(path, NULL) == CSTORE_BAD_ARG);

    setenv("SECURE_ECU_COUNTER_FILE", "/tmp/custom_counter", 1);
    CHECK("env var overrides the path",
          cstore_resolve_path(buf, sizeof(buf)) == 0 && strcmp(buf, "/tmp/custom_counter") == 0);
    unsetenv("SECURE_ECU_COUNTER_FILE");
    setenv("HOME", "/home/tester", 1);
    CHECK("default path is under HOME",
          cstore_resolve_path(buf, sizeof(buf)) == 0
          && strcmp(buf, "/home/tester/.secure_ecu_counter") == 0);
    CHECK("path too long for buffer is rejected", cstore_resolve_path(buf, 8U) == -1);
    unsetenv("HOME");
    CHECK("no env and no HOME fails", cstore_resolve_path(buf, sizeof(buf)) == -1);

    (void)unlink(path);
    (void)unlink(tmp);
    (void)rmdir(dir);

    if (g_failed != 0) {
        printf("%d of %d counter store tests FAILED.\n", g_failed, g_run);
        return 1;
    }
    printf("All %d counter store tests passed.\n", g_run);
    return 0;
}
