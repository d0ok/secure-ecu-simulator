#define _POSIX_C_SOURCE 200809L

#include "counter_store.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int cstore_resolve_path(char *out, size_t len)
{
    const char *env = getenv("SECURE_ECU_COUNTER_FILE");
    const char *home;
    int n;

    if (out == NULL || len == 0U) {
        return -1;
    }
    if (env != NULL && env[0] != '\0') {
        n = snprintf(out, len, "%s", env);
    } else {
        home = getenv("HOME");
        if (home == NULL || home[0] == '\0') {
            return -1;
        }
        n = snprintf(out, len, "%s/.secure_ecu_counter", home);
    }
    return (n < 0 || (size_t)n >= len) ? -1 : 0;
}

cstore_status_t cstore_load(const char *path, uint32_t *counter)
{
    FILE *f;
    char buf[128];
    char *p;
    unsigned long value, check;
    int pos = 0;
    int extra;
    int read_failed;

    if (path == NULL || counter == NULL) {
        return CSTORE_BAD_ARG;
    }

    f = fopen(path, "r");
    if (f == NULL) {
        return (errno == ENOENT) ? CSTORE_NOT_FOUND : CSTORE_IO_ERROR;
    }
    if (fgets(buf, sizeof(buf), f) == NULL) {
        read_failed = ferror(f);
        (void)fclose(f);
        return read_failed ? CSTORE_IO_ERROR : CSTORE_CORRUPT;   /* empty file */
    }
    extra = fgetc(f);
    (void)fclose(f);
    if (extra != EOF) {
        return CSTORE_CORRUPT;                                   /* more than one line */
    }

    if (strchr(buf, '-') != NULL || buf[0] != 'v' || buf[1] != '1' || buf[2] != ' ') {
        return CSTORE_CORRUPT;
    }
    if (sscanf(buf, "v1 %lu %lx%n", &value, &check, &pos) != 2) {
        return CSTORE_CORRUPT;
    }
    for (p = buf + pos; *p != '\0'; p++) {
        if (!isspace((unsigned char)*p)) {
            return CSTORE_CORRUPT;                               /* trailing text */
        }
    }
    if (value > 0xFFFFFFFFUL || check != ((~value) & 0xFFFFFFFFUL)) {
        return CSTORE_CORRUPT;
    }

    *counter = (uint32_t)value;
    return CSTORE_OK;
}

cstore_status_t cstore_save(const char *path, uint32_t counter)
{
    char tmp[CSTORE_PATH_MAX];
    char line[64];
    int n;
    int fd;
    size_t len;

    if (path == NULL) {
        return CSTORE_BAD_ARG;
    }
    n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        return CSTORE_BAD_ARG;
    }
    n = snprintf(line, sizeof(line), "v1 %lu %08lx\n",
                 (unsigned long)counter,
                 (~(unsigned long)counter) & 0xFFFFFFFFUL);
    if (n < 0 || (size_t)n >= sizeof(line)) {
        return CSTORE_IO_ERROR;
    }
    len = (size_t)n;

    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return CSTORE_IO_ERROR;
    }
    if (write(fd, line, len) != (ssize_t)len || fsync(fd) != 0) {
        (void)close(fd);
        (void)unlink(tmp);
        return CSTORE_IO_ERROR;
    }
    if (close(fd) != 0) {
        (void)unlink(tmp);
        return CSTORE_IO_ERROR;
    }
    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return CSTORE_IO_ERROR;
    }
    return CSTORE_OK;
}

const char *cstore_status_str(cstore_status_t status)
{
    switch (status) {
    case CSTORE_OK:        return "ok";
    case CSTORE_NOT_FOUND: return "counter file not found";
    case CSTORE_CORRUPT:   return "counter file is corrupt";
    case CSTORE_IO_ERROR:  return "counter file I/O error";
    case CSTORE_BAD_ARG:   return "invalid argument";
    }
    return "unknown";
}
