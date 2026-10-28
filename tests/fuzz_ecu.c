/*
 * Deterministic fuzz and property tests for the secure ECU simulator.
 *
 * Usage: fuzz_ecu [iterations] [seed]
 *
 * Built with AddressSanitizer and UndefinedBehaviorSanitizer by `make fuzz`.
 * The run is reproducible: the same seed always generates the same cases.
 * Any violated property is printed with the phase and iteration number, and
 * the program exits with status 1.
 */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "counter_store.h"
#include "ecu_app.h"
#include "freshness.h"
#include "sec_layer.h"
#include "secoc.h"

/* ---------- reproducible random numbers (xorshift64*) ---------- */

static uint64_t g_rng;

static uint64_t rnd64(void)
{
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    return g_rng * 0x2545F4914F6CDD1DULL;
}

static uint32_t rnd32(void)
{
    return (uint32_t)(rnd64() >> 32);
}

static uint32_t below(uint32_t n)           /* uniform-ish in [0, n), n > 0 */
{
    return rnd32() % n;
}

static void rnd_bytes(uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)rnd32();
    }
}

/* ---------- reporting ---------- */

static const char *g_phase = "";
static uint64_t g_iter;
static uint64_t g_violations;
static uint64_t g_cases;

#define VIOLATION(...) do { \
    g_violations++; \
    if (g_violations <= 10U) { \
        printf("[VIOLATION] %s, iteration %" PRIu64 ": ", g_phase, g_iter); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

/* ---------- value generators shared by several phases ---------- */

static uint32_t pick_last(void)
{
    switch (below(6)) {
    case 0:  return 0U;
    case 1:  return below(100U);
    case 2:  return UINT32_MAX;
    case 3:  return UINT32_MAX - below(4U);
    case 4:  return 0x7FFFFFF0U + below(32U);
    default: return rnd32();
    }
}

static uint32_t pick_max_jump(void)
{
    static const uint32_t jumps[] = { 0U, 1U, 2U, 10U, 1000U, 0x7FFFFFFFU, UINT32_MAX };
    return jumps[below(7U)];
}

static uint32_t pick_counter(uint32_t last, uint32_t max_jump)
{
    switch (below(10)) {
    case 0:  return last;
    case 1:  return last - 1U;                    /* wraps when last == 0 */
    case 2:  return last + 1U;                    /* wraps at UINT32_MAX */
    case 3:  return last + max_jump;
    case 4:  return last + max_jump + 1U;
    case 5:  return rnd32();
    case 6:  return 0U;
    case 7:  return UINT32_MAX;
    case 8:  return last + 1U + below(5U);
    default: return last - below(5U);
    }
}

/* Independent statement of the freshness rules, written with 64-bit math. */
static int freshness_expected_ok(uint32_t last, uint32_t recv, uint32_t max_jump)
{
    if (last == UINT32_MAX) {
        return 0;
    }
    if (recv <= last) {
        return 0;
    }
    if (max_jump != 0U && ((uint64_t)recv - (uint64_t)last) > (uint64_t)max_jump) {
        return 0;
    }
    return 1;
}

/* ---------- phase 1: freshness manager against the model ---------- */

static void fuzz_freshness(uint64_t iters)
{
    uint64_t i;

    g_phase = "freshness";
    for (i = 0; i < iters; i++) {
        freshness_t f;
        uint32_t max_jump = pick_max_jump();
        uint32_t last = pick_last();
        uint32_t recv = pick_counter(last, max_jump);
        int expect_ok = freshness_expected_ok(last, recv, max_jump);
        freshness_status_t st;

        g_iter = i;
        g_cases++;
        freshness_init(&f, last, max_jump);
        st = freshness_accept(&f, recv);

        if (expect_ok) {
            if (st != FRESHNESS_OK || f.last_accepted != recv) {
                VIOLATION("last=%u recv=%u max=%u: expected accept, got %s",
                          last, recv, max_jump, freshness_status_str(st));
            }
        } else {
            if (st == FRESHNESS_OK) {
                VIOLATION("last=%u recv=%u max=%u: accepted a counter that must be rejected",
                          last, recv, max_jump);
            }
            if (f.last_accepted != last) {
                VIOLATION("last=%u recv=%u max=%u: rejection changed the stored counter",
                          last, recv, max_jump);
            }
        }
    }
}

/* ---------- phase 2: key parsing ---------- */

static void fuzz_key_parse(uint64_t iters)
{
    static const char hexchars[] = "0123456789abcdefABCDEF";
    uint8_t key[SECOC_KEY_LEN];
    uint64_t i;

    g_phase = "key parsing";
    g_iter = 0;
    if (secoc_parse_key_hex(NULL, key) != 0) {
        VIOLATION("NULL key string was accepted");
    }

    for (i = 0; i < iters; i++) {
        size_t len = below(2U) ? (size_t)(62U + below(5U)) : (size_t)below(100U);
        unsigned kind = below(4U);
        char *s = malloc(len + 1U);
        size_t j;
        int all_hex = 1;
        int rc;

        g_iter = i;
        g_cases++;
        if (s == NULL) {
            VIOLATION("out of memory");
            return;
        }
        for (j = 0; j < len; j++) {
            switch (kind) {
            case 0:  s[j] = hexchars[below(16U)]; break;           /* lower-case hex */
            case 1:  s[j] = hexchars[below(22U)]; break;           /* either case */
            case 2:  s[j] = hexchars[below(22U)]; break;           /* one bad byte below */
            default: s[j] = (char)(1U + below(255U)); break;       /* arbitrary non-NUL */
            }
        }
        if (kind == 2U && len > 0U) {
            s[below((uint32_t)len)] = (char)(1U + below(255U));
        }
        s[len] = '\0';

        for (j = 0; j < len; j++) {
            if (!isxdigit((unsigned char)s[j])) {
                all_hex = 0;
            }
        }
        memset(key, 0, sizeof(key));
        rc = secoc_parse_key_hex(s, key);

        if (rc != 0 && !(len == SECOC_KEY_HEX_LEN && all_hex)) {
            VIOLATION("accepted an invalid key string of length %zu", len);
        }
        if (rc == 0 && kind == 0U && len == SECOC_KEY_HEX_LEN) {
            VIOLATION("rejected a valid 64-character lower-case hex key");
        }
        free(s);
    }
}

/* ---------- phase 3: payload verification on exact-size heap buffers ---------- */

static void fuzz_verify(uint64_t iters, const uint8_t key[SECOC_KEY_LEN])
{
    uint64_t i;

    g_phase = "payload verification";
    for (i = 0; i < iters; i++) {
        size_t len = below(2U) ? SECOC_PAYLOAD_LEN : (size_t)below(80U);
        uint8_t *buf = malloc(len ? len : 1U);
        uint32_t id = below(2U) ? SECOC_CAN_ID : rnd32();
        uint8_t good[SECOC_PAYLOAD_LEN];
        uint8_t params[SECOC_PARAMS_LEN];
        uint32_t fresh = rnd32();
        uint8_t cmd = (uint8_t)rnd32();
        uint8_t *shorter, *longer;

        g_iter = i;
        g_cases++;
        if (buf == NULL) {
            VIOLATION("out of memory");
            return;
        }

        /* Random bytes essentially never form a valid tag. */
        rnd_bytes(buf, len);
        if (secoc_verify_payload(key, id, buf, len) != 0) {
            VIOLATION("random payload of length %zu verified", len);
        }
        if (len == SECOC_PAYLOAD_LEN) {
            uint32_t want = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16)
                          | ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
            if (secoc_payload_freshness(buf) != want) {
                VIOLATION("freshness field decoded incorrectly");
            }
        }
        free(buf);

        /* A correctly built payload verifies, and only under its own CAN ID. */
        rnd_bytes(params, sizeof(params));
        if (!secoc_build_payload(key, SECOC_CAN_ID, cmd, params, fresh, good)) {
            VIOLATION("payload construction failed");
            continue;
        }
        if (secoc_verify_payload(key, SECOC_CAN_ID, good, sizeof(good)) != 1) {
            VIOLATION("a correctly built payload did not verify");
        }
        if (secoc_verify_payload(key, SECOC_CAN_ID ^ (1U << below(11U)), good, sizeof(good)) != 0) {
            VIOLATION("payload verified under a different CAN ID");
        }
        good[below(SECOC_PAYLOAD_LEN)] ^= (uint8_t)(1U << below(8U));
        if (secoc_verify_payload(key, SECOC_CAN_ID, good, sizeof(good)) != 0) {
            VIOLATION("payload with a flipped bit verified");
        }
        good[0] ^= 0U;

        /* Wrong lengths on exact-size heap copies: an over-read would be caught by ASan. */
        shorter = malloc(SECOC_PAYLOAD_LEN - 1U);
        longer = malloc(SECOC_PAYLOAD_LEN + 1U);
        if (shorter == NULL || longer == NULL) {
            free(shorter);
            free(longer);
            VIOLATION("out of memory");
            return;
        }
        rnd_bytes(shorter, SECOC_PAYLOAD_LEN - 1U);
        rnd_bytes(longer, SECOC_PAYLOAD_LEN + 1U);
        if (secoc_verify_payload(key, SECOC_CAN_ID, shorter, SECOC_PAYLOAD_LEN - 1U) != 0
            || secoc_verify_payload(key, SECOC_CAN_ID, longer, SECOC_PAYLOAD_LEN + 1U) != 0) {
            VIOLATION("payload with the wrong length verified");
        }
        free(shorter);
        free(longer);
    }
}

/* ---------- phase 4: security layer ---------- */

typedef struct {
    can_msg_t msg;
    uint8_t   command;
    uint8_t   params[SECOC_PARAMS_LEN];
    uint32_t  fresh;
} signed_frame_t;

static void make_signed(signed_frame_t *sf, const uint8_t key[SECOC_KEY_LEN],
                        uint32_t sign_id, uint32_t fresh)
{
    memset(sf, 0, sizeof(*sf));
    sf->command = (uint8_t)rnd32();
    rnd_bytes(sf->params, sizeof(sf->params));
    sf->fresh = fresh;
    rnd_bytes(sf->msg.data, sizeof(sf->msg.data));       /* trailing bytes are random too */
    if (!secoc_build_payload(key, sign_id, sf->command, sf->params, fresh, sf->msg.data)) {
        VIOLATION("payload construction failed");
    }
    sf->msg.id = SECOC_CAN_ID;
    sf->msg.len = (uint8_t)SECOC_PAYLOAD_LEN;
    sf->msg.is_fd = 1;
}

static int same_frame(const can_msg_t *a, const can_msg_t *b)
{
    return a->id == b->id && a->len == b->len && a->is_fd == b->is_fd
        && a->is_extended == b->is_extended && a->is_rtr == b->is_rtr
        && a->is_error == b->is_error
        && memcmp(a->data, b->data, SECOC_PAYLOAD_LEN) == 0;
}

/* Change a frame in at least one authenticated or structural field. */
static void mutate(can_msg_t *m)
{
    const can_msg_t orig = *m;

    do {
        *m = orig;
        switch (below(7U)) {
        case 0:  m->data[below(SECOC_PAYLOAD_LEN)] ^= (uint8_t)(1U << below(8U)); break;
        case 1:  m->data[below(SECOC_PAYLOAD_LEN)] = (uint8_t)rnd32(); break;
        case 2:  m->id = rnd32() & 0x7FFU; break;
        case 3:  m->len = (uint8_t)below(65U); break;
        case 4:  m->is_fd ^= 1; break;
        case 5:
            switch (below(3U)) {
            case 0:  m->is_extended = 1; break;
            case 1:  m->is_rtr = 1; break;
            default: m->is_error = 1; break;
            }
            break;
        default: {
            uint32_t k, n = 1U + below(4U);
            for (k = 0; k < n; k++) {
                m->data[below(SECOC_PAYLOAD_LEN)] ^= (uint8_t)(1U << below(8U));
            }
            break;
        }
        }
    } while (same_frame(&orig, m));
}

#define HIST 16U

static void fuzz_sec_layer(uint64_t iters, const uint8_t key[SECOC_KEY_LEN])
{
    sec_ctx_t sec;
    signed_frame_t hist[HIST];
    unsigned n_hist = 0U, hist_next = 0U;
    uint32_t max_jump = 1000U;
    uint64_t accepted = 0U, replays_rejected = 0U, mac_rejected = 0U;
    uint64_t i;

    g_phase = "security layer";
    memset(&sec, 0, sizeof(sec));
    sec_init(&sec, key, max_jump);

    for (i = 0; i < iters; i++) {
        sec_result_t res;
        signed_frame_t sf;
        uint32_t before;
        unsigned choice;
        sec_status_t rc;

        g_iter = i;
        g_cases++;

        if (i % 256U == 0U) {                                 /* new state, new limits */
            max_jump = pick_max_jump();
            sec_init(&sec, key, max_jump);
            sec.freshness.last_accepted = pick_last();
            n_hist = 0U;
            hist_next = 0U;
        }
        before = sec.freshness.last_accepted;
        choice = below(100U);

        if (choice < 40U) {
            /* Correctly signed frame: outcome must match the freshness rules exactly. */
            uint32_t fresh = pick_counter(before, max_jump);
            int expect_ok = freshness_expected_ok(before, fresh, max_jump);

            make_signed(&sf, key, SECOC_CAN_ID, fresh);
            rc = sec_process(&sec, &sf.msg, &res);
            if (rc != res.status) {
                VIOLATION("return value %d differs from result status %d", rc, res.status);
            }
            if (expect_ok) {
                if (rc != SEC_OK || sec.freshness.last_accepted != fresh) {
                    VIOLATION("fresh counter %u (last %u, max %u) was not accepted", fresh, before, max_jump);
                } else if (res.command != sf.command || memcmp(res.params, sf.params, sizeof(sf.params)) != 0
                           || res.freshness != fresh) {
                    VIOLATION("accepted frame was decoded incorrectly");
                } else {
                    accepted++;
                    hist[hist_next % HIST] = sf;
                    hist_next++;
                    if (n_hist < HIST) {
                        n_hist++;
                    }
                }
            } else {
                if (rc != SEC_ERR_FRESHNESS) {
                    VIOLATION("counter %u (last %u, max %u) should be a freshness failure, got status %d",
                              fresh, before, max_jump, rc);
                }
                if (sec.freshness.last_accepted != before) {
                    VIOLATION("rejected frame changed the stored counter");
                }
            }
        } else if (choice < 55U) {
            /* Replay of a frame that was accepted earlier in this state. */
            if (n_hist > 0U) {
                const signed_frame_t *old = &hist[below(n_hist)];

                rc = sec_process(&sec, &old->msg, &res);
                if (rc == SEC_OK) {
                    VIOLATION("replayed frame with counter %u was accepted", old->fresh);
                } else if (rc != SEC_ERR_FRESHNESS) {
                    VIOLATION("replayed frame gave status %d instead of a freshness failure", rc);
                } else {
                    replays_rejected++;
                }
                if (sec.freshness.last_accepted != before) {
                    VIOLATION("replay changed the stored counter");
                }
            }
        } else if (choice < 70U) {
            /* A valid, acceptable frame with any field changed must be rejected. */
            make_signed(&sf, key, SECOC_CAN_ID, before + 1U);
            mutate(&sf.msg);
            rc = sec_process(&sec, &sf.msg, &res);
            if (rc == SEC_OK) {
                VIOLATION("a mutated frame was accepted");
            }
            if (sec.freshness.last_accepted != before) {
                VIOLATION("a mutated frame changed the stored counter");
            }
        } else if (choice < 80U) {
            /* Signed with the wrong key or for another CAN ID: must fail authentication. */
            uint8_t other[SECOC_KEY_LEN];
            int wrong_key = (int)below(2U);

            rnd_bytes(other, sizeof(other));
            if (memcmp(other, key, sizeof(other)) == 0) {
                continue;
            }
            make_signed(&sf, wrong_key ? other : key,
                        wrong_key ? SECOC_CAN_ID : (SECOC_CAN_ID ^ (1U << below(11U))),
                        before + 1U);
            rc = sec_process(&sec, &sf.msg, &res);
            if (rc != SEC_ERR_MAC) {
                VIOLATION("frame with a wrong %s gave status %d instead of an authentication failure",
                          wrong_key ? "key" : "signing identifier", rc);
            } else {
                mac_rejected++;
            }
            if (sec.freshness.last_accepted != before) {
                VIOLATION("a forged frame changed the stored counter");
            }
        } else {
            /* Garbage. Half of it has a plausible structure so it reaches the HMAC check. */
            can_msg_t m;

            memset(&m, 0, sizeof(m));
            rnd_bytes(m.data, sizeof(m.data));
            if (below(2U)) {
                m.id = SECOC_CAN_ID;
                m.len = (uint8_t)SECOC_PAYLOAD_LEN;
                m.is_fd = 1;
                rc = sec_process(&sec, &m, &res);
                if (rc != SEC_ERR_MAC) {
                    VIOLATION("well-formed frame with a random tag gave status %d", rc);
                } else {
                    mac_rejected++;
                }
            } else {
                m.id = rnd32();
                m.len = (uint8_t)rnd32();
                m.is_fd = (int)below(2U);
                m.is_extended = (int)below(2U);
                m.is_rtr = (int)below(2U);
                m.is_error = (int)below(2U);
                rc = sec_process(&sec, &m, &res);
                if (rc == SEC_OK) {
                    VIOLATION("a random frame was accepted");
                }
            }
            if (sec.freshness.last_accepted != before) {
                VIOLATION("a garbage frame changed the stored counter");
            }
        }
    }

    {
        sec_result_t res;
        signed_frame_t sf;

        make_signed(&sf, key, SECOC_CAN_ID, 1U);
        if (sec_process(NULL, &sf.msg, &res) != SEC_ERR_ARG
            || sec_process(&sec, NULL, &res) != SEC_ERR_ARG
            || sec_process(&sec, &sf.msg, NULL) != SEC_ERR_ARG) {
            VIOLATION("NULL arguments were not rejected");
        }
    }
    sec_close(&sec);
    printf("  security layer: %" PRIu64 " valid frames accepted, %" PRIu64
           " replays rejected, %" PRIu64 " authentication failures\n",
           accepted, replays_rejected, mac_rejected);
}

/* ---------- phase 5: ECU application ---------- */

static void fuzz_ecu_app(uint64_t iters)
{
    ecu_app_t app;
    int m_locked = 0;
    uint32_t m_count = 0U;
    uint64_t i;
    uint8_t params[SECOC_PARAMS_LEN];

    g_phase = "ECU application";
    ecu_app_init(&app);
    rnd_bytes(params, sizeof(params));

    for (i = 0; i < iters; i++) {
        static const uint8_t known[] = { ECU_CMD_LOCK, ECU_CMD_UNLOCK, ECU_CMD_STATUS, ECU_CMD_PING };
        uint8_t cmd = below(10U) < 6U ? known[below(4U)] : (uint8_t)rnd32();
        size_t out_len = (size_t)below(80U);
        char *out = malloc(out_len ? out_len : 1U);
        int supported = (cmd == ECU_CMD_LOCK || cmd == ECU_CMD_UNLOCK
                         || cmd == ECU_CMD_STATUS || cmd == ECU_CMD_PING);
        char expected_status[64];
        ecu_status_t rc;

        g_iter = i;
        g_cases++;
        if (out == NULL) {
            VIOLATION("out of memory");
            return;
        }
        memset(out, 0x5A, out_len ? out_len : 1U);
        (void)snprintf(expected_status, sizeof(expected_status), "state=%s executed=%u",
                       m_locked ? "LOCKED" : "UNLOCKED", (unsigned int)m_count);

        rc = ecu_app_execute(&app, cmd, below(2U) ? params : NULL, out, out_len);

        if (out_len == 0U) {
            if (rc != ECU_ERR_ARG) {
                VIOLATION("zero-length output buffer was not rejected");
            }
        } else {
            if (memchr(out, '\0', out_len) == NULL) {
                VIOLATION("output is not NUL-terminated within %zu bytes", out_len);
            }
            if (supported && rc != ECU_OK) {
                VIOLATION("supported command 0x%02X failed", (unsigned int)cmd);
            }
            if (!supported && rc != ECU_ERR_UNSUPPORTED) {
                VIOLATION("unsupported command 0x%02X was not reported", (unsigned int)cmd);
            }
            if (supported && rc == ECU_OK) {
                if (cmd == ECU_CMD_LOCK) {
                    m_locked = 1;
                } else if (cmd == ECU_CMD_UNLOCK) {
                    m_locked = 0;
                }
                m_count++;
                if (cmd == ECU_CMD_STATUS && out_len >= sizeof(expected_status)
                    && strcmp(out, expected_status) != 0) {
                    VIOLATION("status text is \"%s\", expected \"%s\"", out, expected_status);
                }
            }
        }
        if (app.locked != m_locked || app.commands_executed != m_count) {
            VIOLATION("application state diverged from the model after command 0x%02X",
                      (unsigned int)cmd);
            m_locked = app.locked;
            m_count = app.commands_executed;
        }
        free(out);
    }

    {
        char out[16];
        if (ecu_app_execute(NULL, ECU_CMD_PING, params, out, sizeof(out)) != ECU_ERR_ARG
            || ecu_app_execute(&app, ECU_CMD_PING, params, NULL, sizeof(out)) != ECU_ERR_ARG) {
            VIOLATION("NULL arguments were not rejected");
        }
    }
}

/* ---------- phase 6: counter file parsing and saving ---------- */

static void write_bytes(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f != NULL) {
        if (len > 0U) {
            (void)fwrite(data, 1, len, f);
        }
        (void)fclose(f);
    }
}

static void fuzz_counter_store(uint64_t iters)
{
    char dir[] = "/tmp/fuzz_ecu_XXXXXX";
    char path[128], tmp[136];
    uint64_t i;

    g_phase = "counter store";
    if (mkdtemp(dir) == NULL) {
        VIOLATION("cannot create a temporary directory");
        return;
    }
    (void)snprintf(path, sizeof(path), "%s/counter", dir);
    (void)snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    for (i = 0; i < iters; i++) {
        uint8_t buf[512];
        char line[96];
        uint32_t out = 0U;
        uint32_t value = pick_last();
        unsigned kind = below(4U);
        size_t len;
        cstore_status_t st;

        g_iter = i;
        g_cases++;

        if (kind == 0U) {
            /* Arbitrary bytes, including NULs and very long files. */
            len = (size_t)below(sizeof(buf));
            rnd_bytes(buf, len);
            write_bytes(path, buf, len);
            st = cstore_load(path, &out);
            if (st == CSTORE_OK && memchr(buf, '-', len) != NULL) {
                VIOLATION("accepted a counter file containing a minus sign");
            }
        } else if (kind == 1U) {
            /* Well-formed text with a right or wrong check value. */
            unsigned long check = (~(unsigned long)value) & 0xFFFFFFFFUL;
            int good = (int)below(2U);

            if (!good) {
                check ^= 1UL << below(32U);
            }
            len = (size_t)snprintf(line, sizeof(line), "v1 %lu %lx\n", (unsigned long)value, check);
            write_bytes(path, (const uint8_t *)line, len);
            st = cstore_load(path, &out);
            if (good && (st != CSTORE_OK || out != value)) {
                VIOLATION("valid record for %u was not loaded (status %d)", value, (int)st);
            }
            if (!good && st == CSTORE_OK) {
                VIOLATION("record with a wrong check value was accepted");
            }
        } else if (kind == 2U) {
            /* A valid record with one byte replaced: it may only load as the same value. */
            len = (size_t)snprintf(line, sizeof(line), "v1 %lu %08lx\n", (unsigned long)value,
                                   (~(unsigned long)value) & 0xFFFFFFFFUL);
            line[below((uint32_t)len)] = (char)rnd32();
            write_bytes(path, (const uint8_t *)line, len);
            st = cstore_load(path, &out);
            if (st == CSTORE_OK && out != value) {
                VIOLATION("a damaged record for %u loaded as %u", value, out);
            }
        } else {
            /* Save then load, and no temporary file may remain. */
            if (i % 50U != 0U) {
                continue;                                  /* saving syncs to disk: keep it rare */
            }
            if (cstore_save(path, value) != CSTORE_OK) {
                VIOLATION("save of %u failed", value);
            } else if (cstore_load(path, &out) != CSTORE_OK || out != value) {
                VIOLATION("saved counter %u did not load back", value);
            }
            if (access(tmp, F_OK) == 0) {
                VIOLATION("temporary file left behind after a save");
            }
        }
    }

    (void)unlink(path);
    (void)unlink(tmp);
    (void)rmdir(dir);
}

/* ---------- driver ---------- */

int main(int argc, char **argv)
{
    uint64_t iters = 100000U;
    uint64_t seed = 1U;
    uint8_t key[SECOC_KEY_LEN];

    if (argc > 1) {
        iters = strtoull(argv[1], NULL, 10);
    }
    if (argc > 2) {
        seed = strtoull(argv[2], NULL, 10);
    }
    if (iters == 0U) {
        iters = 1U;
    }
    g_rng = seed * 0x9E3779B97F4A7C15ULL + 0x1234567ULL;
    if (g_rng == 0U) {
        g_rng = 1U;
    }
    rnd_bytes(key, sizeof(key));

    printf("Fuzzing with seed %" PRIu64 ", %" PRIu64 " iterations per phase\n", seed, iters);

    fuzz_freshness(iters);
    fuzz_key_parse(iters);
    fuzz_verify(iters / 4U + 1U, key);
    fuzz_sec_layer(iters, key);
    fuzz_ecu_app(iters);
    fuzz_counter_store(iters / 20U + 200U);

    if (g_violations != 0U) {
        printf("FUZZ FAILED: %" PRIu64 " violations in %" PRIu64 " cases (seed %" PRIu64 ")\n",
               g_violations, g_cases, seed);
        return 1;
    }
    printf("FUZZ PASSED: %" PRIu64 " cases, no violations, no sanitizer findings (seed %" PRIu64 ")\n",
           g_cases, seed);
    return 0;
}
