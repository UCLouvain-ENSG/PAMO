/* Copyright (C) 2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-build.h"

#include "conf.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-memcmp.h"
#include "util-mpm-rxp.h"
#include "util-memcpy.h"
#include "util-hash.h"
#include "util-hash-lookup3.h"
#include "util-hyperscan.h"

#include <rte_regexdev.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_dev.h>
#include <threads.h>

#include <hs.h>
#include <openssl/evp.h>

#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)>(b)?(b):(a))

#define MPM_RXP_DEFAULT_DESCRIPTORS 256 // descriptors used in the rxp queues
#define MPM_RXP_MAX_WORKERS 32
#define MPM_RXP_PATTERNS_PATH "/tmp/suricata-mpm.patterns" // path to where extracted contents from Suricata rules will be temporarily stored
#define MPM_RXP_RXPC_OUTPUT_PREFIX_PATH "/tmp/suricata-rules"
#define MPM_RXP_RULES_PATH MPM_RXP_RXPC_OUTPUT_PREFIX_PATH ".rof2.binary" // path to the rules file with all MPM contexts after it was compiled from the contents of Suricata rules

typedef struct SCRXPPatternDB_ {
    SCRXPPattern **parray;
    uint32_t pattern_cnt;
    uint32_t parray_capacity;
} SCRXPPatternDB;
/* Global array of RXP Patterns, used for a conversion from DPDK RGX match rule ID to SCRXPPattern. 
    Access is done through a global pattern ID */
static SCRXPPatternDB g_pat_db = {0};

static uint32_t g_rxp_mpm_ids_capa = 0;
static bool *g_rxp_mpm_ids = NULL;
static bool g_rxp_mpm_ids_all = false;
// Global mbuf mempool
thread_local struct rte_mempool *g_rxp_op_mp = NULL;
// a shared variable for each worker to pick their work queue ID
rte_atomic16_t g_wq_id;

thread_local uint16_t g_rxp_qid = UINT16_MAX;
thread_local struct rte_regex_ops **g_rxp_ops = NULL; // a helper structure, MLX copies contents of it to BF-specific ops before transmitting those to the HW
thread_local int g_rxp_ops_idx = 0;
thread_local uint16_t g_wq_id_local = UINT16_MAX;
thread_local void *g_rxp_prev_scanned_buffer = NULL;

static void
extbuf_free_cb(void *addr __rte_unused, void *fcb_opaque __rte_unused)
{
    // empty function because the buffer is managed by Suricata
}

struct rte_mbuf_ext_shared_info shinfo = {
    .free_cb = extbuf_free_cb,
    .fcb_opaque = NULL,
};

typedef struct RXPStats_ {
    uint64_t g_rxp_searches;
    uint64_t g_rxp_searched_bytes;
    uint64_t g_rxp_buffers;
    uint64_t g_rxp_buffers_uniq;
    uint64_t g_rxp_failed_mp_gets;
    uint64_t g_rxp_no_packet;
    uint64_t g_rxp_failed_enqueues;
    uint64_t g_rxp_skipped_enqueues;
    uint64_t g_hs_searches;
    uint64_t g_hs_searched_bytes;
    uint64_t g_rxp_error;
    uint64_t g_rxp_timeout_error;
    uint64_t g_rxp_max_match_error;
    uint64_t g_rxp_max_prefix_error;
    uint64_t g_rxp_max_limit_error;
} RXPStats;

RXPStats stats[MPM_RXP_MAX_WORKERS];


static long read_file(const char *file, char **buf) {
    FILE *fp;
    long buf_len = 0;
    size_t read_len;
    int res = 0;

    fp = fopen(file, "r");
    if (!fp)
        return -EIO;
    if (fseek(fp, 0L, SEEK_END) == 0) {
        buf_len = ftell(fp);
        if (buf_len == -1) {
            res = EIO;
            goto error;
        }
        *buf = rte_malloc(NULL, sizeof(char) * (buf_len + 1), 4096);
        if (!*buf) {
            res = ENOMEM;
            goto error;
        }
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            res = EIO;
            goto error;
        }
        read_len = fread(*buf, sizeof(char), buf_len, fp);
        if (read_len != (unsigned long)buf_len) {
            res = EIO;
            goto error;
        }
    }
    fclose(fp);
    return buf_len;
error:
    printf("Error, can't open file %s\n, err = %d", file, res);
    if (fp)
        fclose(fp);
    rte_free(*buf);
    return -res;
}


void SCRXPInitCtx(MpmCtx *);
void SCRXPInitThreadCtx(MpmCtx *, MpmThreadCtx *);
void SCRXPDestroyCtx(MpmCtx *);
void SCRXPDestroyThreadCtx(MpmCtx *, MpmThreadCtx *);
int SCRXPAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, SigIntId, uint8_t);
int SCRXPAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, SigIntId, uint8_t);
int SCRXPPreparePatterns(MpmCtx *mpm_ctx);
static inline uint32_t SCRXPSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen, Packet *p);
void SCRXPPrintInfo(MpmCtx *mpm_ctx);
void SCRXPPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
#ifdef UNITTESTS
static void SCRXPRegisterTests(void);
#endif

/* size of the hash table used to speed up pattern insertions initially */
#define INIT_HASH_SIZE 65536

/* Initial size of the global database hash (used for de-duplication). */
#define INIT_DB_HASH_SIZE 1000

/**
 * \internal
 * \brief Creates a hash of the pattern.  We use it for the hashing process
 *        during the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline uint32_t SCRXPInitHashRaw(uint8_t *pat, uint16_t patlen)
{
    uint32_t hash = patlen * pat[0];
    if (patlen > 1)
        hash += pat[1];

    return (hash % INIT_HASH_SIZE);
}

/**
 * \internal
 * \brief Looks up a pattern.  We use it for the hashing process during
 *        the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param ctx    Pointer to the RXP ctx.
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 * \param flags  Flags.  We don't need this.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline SCRXPPattern *SCRXPInitHashLookup(SCRXPCtx *ctx, uint8_t *pat,
                                              uint16_t patlen, uint16_t offset,
                                              uint16_t depth, char flags,
                                              uint32_t pid)
{
    uint32_t hash = SCRXPInitHashRaw(pat, patlen);

    if (ctx->init_hash == NULL) {
        return NULL;
    }

    SCRXPPattern *t = ctx->init_hash[hash];
    for (; t != NULL; t = t->next) {
        /* We must distinguish between
         * patterns with the same ID but different offset/depth here. */
        if (t->id == pid && t->offset == offset && t->depth == depth) {
            BUG_ON(t->len != patlen);
            BUG_ON(SCMemcmp(t->original_pat, pat, patlen) != 0);
            return t;
        }
    }

    return NULL;
}

/**
 * \internal
 * \brief Allocates a new pattern instance.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval p Pointer to the newly created pattern.
 */
static inline SCRXPPattern *SCRXPAllocPattern(MpmCtx *mpm_ctx)
{
    SCRXPPattern *p = SCCalloc(1, sizeof(SCRXPPattern));
    if (unlikely(p == NULL)) {
        FatalError("not enough memory when allocing pattern");
    }

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCRXPPattern);

    return p;
}

/**
 * \internal
 * \brief Used to free SCRXPPattern instances.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param p       Pointer to the SCRXPPattern instance to be freed.
 * \param free    Free the above pointer or not.
 */
static inline void SCRXPFreePattern(MpmCtx *mpm_ctx, SCRXPPattern *p)
{
    if (p != NULL && p->original_pat != NULL) {
        SCFree(p->original_pat);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->sids != NULL) {
        SCFree(p->sids);
    }

    if (p != NULL) {
        SCFree(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(SCRXPPattern);
    }
}

/**
 * \internal
 * \brief Used to free SCRXPPattern instances.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param p       Pointer to the SCRXPPattern instance to be freed.
 * \param free    Free the above pointer or not.
 */
static inline void SCRXPDestroyInitHash(MpmCtx *mpm_ctx, SCRXPCtx *ctx)
{
    for (uint32_t i = 0; i < INIT_HASH_SIZE; i++) {
        SCRXPPattern *p = ctx->init_hash[i];
        while (p) {
            SCRXPPattern *next = p->next;
            SCRXPFreePattern(mpm_ctx, p);
            p = next;
        }
    }

    SCFree(ctx->init_hash);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= INIT_HASH_SIZE * sizeof(SCRXPPattern *);
}

static inline uint32_t SCRXPInitHash(SCRXPPattern *p)
{
    uint32_t hash = p->len * p->original_pat[0];
    if (p->len > 1)
        hash += p->original_pat[1];

    return (hash % INIT_HASH_SIZE);
}

static inline int SCRXPInitHashAdd(SCRXPCtx *ctx, SCRXPPattern *p)
{
    uint32_t hash = SCRXPInitHashRaw(p->original_pat, p->len);

    if (ctx->init_hash == NULL) {
        return -1;
    }

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        return 0;
    }

    SCRXPPattern *tt = NULL;
    SCRXPPattern *t = ctx->init_hash[hash];

    /* get the list tail */
    do {
        tt = t;
        t = t->next;
    } while (t != NULL);

    tt->next = p;

    return 0;
}

/**
 * \internal
 * \brief Add a pattern to the mpm-hs context.
 *
 * \param mpm_ctx Mpm context.
 * \param pat     Pointer to the pattern.
 * \param patlen  Length of the pattern.
 * \param pid     Pattern id
 * \param sid     Signature id (internal id).
 * \param flags   Pattern's MPM_PATTERN_* flags.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SCRXPAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                          uint16_t offset, uint16_t depth, uint32_t pid,
                          SigIntId sid, uint8_t flags)
{
    SCRXPCtx *ctx = (SCRXPCtx *)mpm_ctx->ctx;

    if (offset != 0) {
        flags |= MPM_PATTERN_FLAG_OFFSET;
    }
    if (depth != 0) {
        flags |= MPM_PATTERN_FLAG_DEPTH;
    }

    if (patlen == 0) {
        SCLogWarning("pattern length 0");
        return 0;
    }

    /* check if we have already inserted this pattern */
    SCRXPPattern *p =
        SCRXPInitHashLookup(ctx, pat, patlen, offset, depth, flags, pid);
    if (p == NULL) {
        SCLogDebug("Allocing new pattern");

        /* p will never be NULL */
        p = SCRXPAllocPattern(mpm_ctx);

        p->len = patlen;
        p->flags = flags;
        p->id = pid;
        p->glob_pattern_id = mpm_ctx_glob_patterns_cnt++;

        p->offset = offset;
        p->depth = depth;

        p->original_pat = SCCalloc(patlen, sizeof(char));
        if (p->original_pat == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy(p->original_pat, pat, patlen);

        /* put in the pattern hash */
        if (SCRXPInitHashAdd(ctx, p) != 0)
            goto error;

        mpm_ctx->pattern_cnt++;

        if (!(mpm_ctx->flags & MPMCTX_FLAGS_NODEPTH)) {
            if (depth) {
                mpm_ctx->maxdepth = MAX(mpm_ctx->maxdepth, depth);
                SCLogDebug("%p: depth %u max %u", mpm_ctx, depth, mpm_ctx->maxdepth);
            } else {
                mpm_ctx->flags |= MPMCTX_FLAGS_NODEPTH;
                mpm_ctx->maxdepth = 0;
                SCLogDebug("%p: alas, no depth for us", mpm_ctx);
            }
        }

        if (mpm_ctx->maxlen < patlen)
            mpm_ctx->maxlen = patlen;

        if (mpm_ctx->minlen == 0) {
            mpm_ctx->minlen = patlen;
        } else {
            if (mpm_ctx->minlen > patlen)
                mpm_ctx->minlen = patlen;
        }

        p->sids_size = 1;
        p->sids = SCCalloc(p->sids_size, sizeof(SigIntId));
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += p->sids_size * sizeof(SigIntId);
        BUG_ON(p->sids == NULL);
        p->sids[0] = sid;
        // char *s = (char *)p->original_pat;
        // SCLogError("pattern - %s ", s);
    } else {
        int found = 0;
        uint32_t x = 0;
        for (x = 0; x < p->sids_size; x++) {
            if (p->sids[x] == sid) {
                found = 1;
                break;
            }
        }
        if (!found) {
            int old_sids_size = p->sids_size;
            SigIntId *sids = SCRealloc(p->sids, (sizeof(SigIntId) * (p->sids_size + 1)));
            BUG_ON(sids == NULL);
            p->sids = sids;
            p->sids[p->sids_size] = sid;
            p->sids_size++;
            // mpm_ctx->memory_cnt++;
            mpm_ctx->memory_size = mpm_ctx->memory_size - old_sids_size * sizeof(SigIntId) + p->sids_size * sizeof(SigIntId);
        }
    }

    return 0;

error:
    SCRXPFreePattern(mpm_ctx, p);
    return -1;
}

static char *RXPRenderPattern(const uint8_t *pat, uint16_t pat_len)
{
    if (pat == NULL) {
        FatalError("Pattern is NULL");
    }
    const size_t hex_len = (pat_len * 4) + 1;
    char *str = SCCalloc(1, hex_len);
    if (str == NULL) {
        FatalError("Memory allocation failed for render pattern");
    }
    char *sp = str;
    for (uint16_t i = 0; i < pat_len; i++) {
        snprintf(sp, 5, "\\x%02x", pat[i]);
        sp += 4;
    }
    *sp = '\0';
    return str;
}

static char *SCRXPPatternsSerialize(MpmCtx *mpm_ctx)
{
    SCRXPCtx *ctx = (SCRXPCtx *)mpm_ctx->ctx;
    // Initial buffer allocation to start with
    int buffer_size = 1024;
    char *buffer = (char *)SCCalloc(buffer_size, sizeof(char));
    if (!buffer) {
        FatalError("Memory allocation failed");
    }

    // Initialize the buffer with the MPM global id
    int offset = snprintf(buffer, buffer_size, "subset_id=%u\n", ctx->mpm_glob_id);
    g_mpm_groups_cnt++;

    // Iterate over the hash table where patterns are stored
    for (uint32_t i = 0; i < INIT_HASH_SIZE; i++) {
        SCRXPPattern *p = ctx->init_hash[i];
        while (p) {
            // Calculate additional buffer space needed for this pattern
            char *pattern_repr = RXPRenderPattern(p->original_pat, p->len);
            char flags_repr[2] = {'\0', '\0'};
            if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                flags_repr[0] = 'i';
            }
            char prefix[64] = "";
            if ((p->flags & MPM_PATTERN_FLAG_DEPTH) && (p->flags & MPM_PATTERN_FLAG_OFFSET)) {
                snprintf(prefix, sizeof(prefix), "^.{%d,%d}", p->offset, p->offset + p->depth - p->len);
            } else if (p->flags & MPM_PATTERN_FLAG_DEPTH) {
                // needs to contain the offset as well to be a valid pattern - cannot be {,depth}
                // rxpc doesn't compile but won't match the same
                if (p->depth - p->len == 0) {
                    // avoiding ^.{0,0} as it is the same as ^
                    // probably NOT needed - evaluate
                    snprintf(prefix, sizeof(prefix), "^");
                } else {
                    snprintf(prefix, sizeof(prefix), "^.{0,%d}", p->depth - p->len);
                }
            } else if (p->flags & MPM_PATTERN_FLAG_OFFSET) {
                if (p->offset == 0) {
                    snprintf(prefix, sizeof(prefix), "^");
                } else {
                    snprintf(prefix, sizeof(prefix), "^.{%d,}", p->offset);
                }
            }

            // Check if buffer needs to be expanded to fit this new pattern line
            uint16_t id_len = snprintf(NULL, 0, "%u,/", p->glob_pattern_id) + 1;
            int extra_space = id_len + strlen(pattern_repr) + strlen(prefix) + strlen(flags_repr);
            extra_space += 1; // NULL character
            while (offset + extra_space >= buffer_size) {
                buffer_size *= 2;
                buffer = SCRealloc(buffer, buffer_size);
                if (!buffer) {
                    fprintf(stderr, "Memory reallocation failed\n");
                    return NULL;
                }
            }

            if (buffer_size - offset < extra_space)
                SCLogError("Bufsz: %u Offset: %u Extra: %d", buffer_size, offset, extra_space);

            // Append formatted pattern to buffer
            offset += snprintf(buffer + offset, buffer_size - offset, 
                               "%u,/%s%s/%s\n", p->glob_pattern_id, prefix, pattern_repr, flags_repr);

            // Move to the next pattern in the linked list
            p = p->next;
        }
    }

    return buffer;
}

/**
 * \brief Write the prepared patterns to a file.
 *
 * \param filename Path to the file where patterns should be written.
 * \param data String containing the formatted patterns.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int WritePatternsToFile(const char *filename, const char *fmode, const char *data) {
    FILE *file = fopen(filename, fmode);
    if (!file) {
        FatalError("Failed to open file %s for writing\n", filename);
    }

    if (fputs(data, file) == EOF) {
        fclose(file);
        FatalError("Failed to write data to file %s\n", filename);
    }

    fclose(file);
    return 0;
}


/**
 * \brief Process the patterns added to the mpm, and create the internal tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
int SCRXPPreparePatterns(MpmCtx *mpm_ctx)
{
    static bool first_write = true;
    SCRXPCtx *ctx = (SCRXPCtx *)mpm_ctx->ctx;
    if (mpm_ctx->pattern_cnt == 0 || ctx->init_hash == NULL) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }

    mpm_table[MPM_HS].Prepare(&ctx->mpm_hs_ctx);
    if (!ctx->rxp_offloaded) {
        SCLogDebug("Skipping pattern preparation, not meant for RXP");
        return 0;
    }

    if (g_pat_db.parray_capacity == 0) {
        g_pat_db.parray_capacity = 131072;
        g_pat_db.parray = SCCalloc(g_pat_db.parray_capacity, sizeof(SCRXPPattern *));
    }

    uint32_t old_capacity = g_pat_db.parray_capacity;
    while (g_pat_db.pattern_cnt + mpm_ctx->pattern_cnt >= g_pat_db.parray_capacity) {
        g_pat_db.parray_capacity *= 2;
        void *tmpptr = SCRealloc(g_pat_db.parray, g_pat_db.parray_capacity * sizeof(SCRXPPattern *));
        g_pat_db.parray = tmpptr;
    }
    if (old_capacity != g_pat_db.parray_capacity) {
        memset(&g_pat_db.parray[old_capacity], 0, (g_pat_db.parray_capacity - old_capacity) * sizeof(SCRXPPattern *));
    }

    // append the patterns to the array
    for (uint32_t i = 0; i < INIT_HASH_SIZE; i++) {
        SCRXPPattern *p = ctx->init_hash[i];
        while (p) {
            uint32_t old_capacity = g_pat_db.parray_capacity;
            while (p->glob_pattern_id > g_pat_db.parray_capacity) {
                g_pat_db.parray_capacity *= 2;
                void *tmpptr = SCRealloc(g_pat_db.parray, g_pat_db.parray_capacity * sizeof(SCRXPPattern *));
                g_pat_db.parray = tmpptr;
            }
            if (old_capacity != g_pat_db.parray_capacity) {
                memset(&g_pat_db.parray[old_capacity], 0, (g_pat_db.parray_capacity - old_capacity) * sizeof(SCRXPPattern *));
            }
            g_pat_db.parray[p->glob_pattern_id] = p; 
            g_pat_db.pattern_cnt++;
            p = p->next;
        }
    }

    // append to a file with some rule group
    //       what if no groups? - if we want to do sw filtration - next work
    //  you need to account for depth and offset
    char *b = SCRXPPatternsSerialize(mpm_ctx);
    if (first_write) { // init value for glob id
        WritePatternsToFile(MPM_RXP_PATTERNS_PATH, "w", b);
        first_write = false;
    } else {
        WritePatternsToFile(MPM_RXP_PATTERNS_PATH, "a", b);
    }
    SCFree(b);
    return 0;
}

// Function to allocate memory for ops and ops_base
struct rte_regex_ops **RXPOpsAlloc(uint16_t ops_cnt, u_int16_t max_matches_cnt) {
    struct rte_regex_ops **ops =
        rte_calloc("regex ops", ops_cnt, sizeof(*ops), 0);
    if (ops == NULL) {
        FatalError("Error, can't allocate memory for ops");
    }

    size_t size_per_ops = sizeof(struct rte_regex_ops) +
                          (max_matches_cnt + 1) * sizeof(struct rte_regexdev_match);

    struct rte_regex_ops *ops_base = rte_calloc(
        "regex ops base", ops_cnt, size_per_ops, 0);

    if (ops_base == NULL) {
        FatalError("Error, can't allocate memory for ops_base");
        // rte_free(ops);
    }

    for (int i = 0; i < ops_cnt; i++) {
        ops[i] = (struct rte_regex_ops *)((char *)ops_base + i * size_per_ops);
        ops[i]->nb_matches = max_matches_cnt;
    }

    return ops;
}

static void RXPOpsDealloc(struct rte_regex_ops **ops) {
    if (ops != NULL) {
        if (ops[0] != NULL)
        rte_free(ops[0]); // just free the first elem because the whole array of
                            // ops is allocated in one go
        rte_free(ops);
    }
    ops = NULL;
}

/**
 * \brief Init the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context - always NULL
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 */
void SCRXPInitThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    SCRXPThreadCtx *ctx = SCCalloc(1, sizeof(SCRXPThreadCtx));
    if (ctx == NULL) {
        FatalError("No memory for RXP Thread CTX");
    }
    mpm_thread_ctx->ctx = ctx;

    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(SCRXPThreadCtx);
    if (g_wq_id_local == UINT16_MAX) {
        g_wq_id_local = rte_atomic16_add_return(&(g_wq_id), 1) - 1;
    }
    ctx->qid = g_wq_id_local;
    ctx->jobs_inprogress = 0;
    ctx->rxp_minlength = g_rxp_minlength > 0? g_rxp_minlength : -g_rxp_minlength;

    ctx->max_jobs_threshold = min(g_rxp_desc - 8,(g_rxp_desc / 2) + 32);
    ctx->min_jobs_threshold = max(8,max(0,((int32_t)g_rxp_desc / 2) - 32));

    SCLogDebug("RXP Min length %d, thresholds %d-%d",g_rxp_minlength,ctx->min_jobs_threshold ,ctx->max_jobs_threshold  );
    struct rte_regexdev_info info;
    int res = rte_regexdev_info_get(0, &info);
    if (res != 0) {
        FatalError("Cannot get device info");
    }

    if (g_rxp_op_mp == NULL) {
        // snprintf name of the mempool
        char mp_name[32];
        snprintf(mp_name, sizeof(mp_name), "rxp_ctx_mp_%u", g_wq_id_local);
        g_rxp_op_mp = rte_mempool_create(mp_name, 262143, sizeof(SCRXPOp), RTE_MEMPOOL_CACHE_MAX_SIZE, 0, NULL, NULL, NULL, NULL, rte_socket_id(), RTE_MEMPOOL_F_NO_CACHE_ALIGN | RTE_MEMPOOL_F_SP_PUT | RTE_MEMPOOL_F_SC_GET);
        if (g_rxp_op_mp == NULL) {
            FatalError("Failed to create MP for RXP OPs: %s", rte_strerror(rte_errno));
        }
    }

    if (g_rxp_ops == NULL) {
        g_rxp_ops = RXPOpsAlloc(MPM_RXP_OPERATIONS * 2, info.max_matches);
        if (!g_rxp_ops) {
            FatalError("Ops not allocated for %u thread", ctx->qid);
        }
    }
    // SCRXPCtx *mpm_ctx_rxp = (SCRXPCtx *)mpm_ctx->ctx;
    mpm_table[MPM_HS].InitThreadCtx(NULL, &ctx->mpm_hs_thread_ctx);
}

static char *RXPGetIfaceNameOfRXP(uint16_t port_id) {
    static char pci_addr_str[RTE_DEV_NAME_MAX_LEN];

    // Check if the port_id is valid
    if (rte_eth_dev_is_valid_port(port_id) == 0) {
        printf("Invalid port ID %u\n", port_id);
        return NULL;
    }

    // Get the name of the device, which typically includes the PCIe address
    if (rte_eth_dev_get_name_by_port(port_id, pci_addr_str) == 0) {
        printf("PCIe address for port %u: %s\n", port_id, pci_addr_str); // <----------------- TODO verify this
    } else {
        printf("Failed to retrieve PCIe address for port %u.\n", port_id);
    }

    return pci_addr_str;
}

/**
 * \brief Function parses array of MPM group ids to offload to RXP
 */
static void LoadMPM2RXPGroupIds(void) 
{
    const char dpdk_node_query[] = "dpdk.interfaces";
    ConfNode *dpdk_node = ConfGetNode(dpdk_node_query);
    if (dpdk_node == NULL) {
        FatalError("Unable to get %s configuration node", dpdk_node_query);
    }

    ConfNode *if_node = ConfNodeLookupKeyValue(dpdk_node, "interface", RXPGetIfaceNameOfRXP(0));
    if (if_node == NULL) {
        FatalError("Unable to get interface configuration node %s", RXPGetIfaceNameOfRXP(0));
    }
    ConfNode *node = ConfNodeLookupChild(if_node, "rxp-mpm-groupids");
    if (node == NULL) {
        g_rxp_mpm_ids_all = true;
        return;
    }
    ConfNode *lnode;

    g_rxp_mpm_ids_capa = 256;
    g_rxp_mpm_ids = SCCalloc(g_rxp_mpm_ids_capa, sizeof(g_rxp_mpm_ids[0]));
    if (g_rxp_mpm_ids == NULL) {
        FatalError("Failed to allocate memory for RXP MPM group ids");
    }

    TAILQ_FOREACH(lnode, &node->head, next)
    {
        uint8_t start, end;
        char *end_str;
        if (strncmp(lnode->val, "all", 4) == 0) {
            g_rxp_mpm_ids_all = true;
        } else if ((end_str = strchr(lnode->val, '-'))) {
            if (StringParseUint8(&start, 10, end_str - lnode->val, (const char *)lnode->val) < 0) {
                FatalError("MPM group id list to RXP offload is invalid"
                            " range start: '%s'",
                        lnode->val);
            }
            if (StringParseUint8(&end, 10, 0, (const char *) (end_str + 1)) < 0) {
                FatalError("MPM group id list to RXP offload is invalid"
                            " range end: '%s'",
                        (end_str != NULL) ? (const char *)(end_str + 1) : "Null");
            }
            if (end < start) {
                FatalError("MPM group id list to RXP offload is invalid"
                            " range start: '%d' is greater than end: '%d'",
                        start, end);
            }
            
            while (start > g_rxp_mpm_ids_capa || end > g_rxp_mpm_ids_capa) {
                uint32_t old_capacity = g_rxp_mpm_ids_capa;
                g_rxp_mpm_ids_capa *= 2;
                g_rxp_mpm_ids = SCRealloc(g_rxp_mpm_ids, g_rxp_mpm_ids_capa * sizeof(g_rxp_mpm_ids[0]));
                if (g_rxp_mpm_ids == NULL) {
                    FatalError("Failed to reallocate memory for RXP MPM group ids");
                }
                memset(&g_rxp_mpm_ids[old_capacity], 0, (g_rxp_mpm_ids_capa - old_capacity) * sizeof(g_rxp_mpm_ids[0]));
            }

            for (uint8_t i = start; i <= end; i++) {
                g_rxp_mpm_ids[i] = true;
                SCLogConfig("MPM group id %u will be offloaded to RXP", i);
            }

        } else {
            if (StringParseUint8(&start, 10, 0, (const char *)lnode->val) < 0) {
                FatalError("MPM group id list to RXP offload is invalid"
                            " range start: '%s'",
                        lnode->val);
            }
            while (start > g_rxp_mpm_ids_capa) {
                uint32_t old_capacity = g_rxp_mpm_ids_capa;
                g_rxp_mpm_ids_capa *= 2;
                g_rxp_mpm_ids = SCRealloc(g_rxp_mpm_ids, g_rxp_mpm_ids_capa * sizeof(g_rxp_mpm_ids[0]));
                if (g_rxp_mpm_ids == NULL) {
                    FatalError("Failed to reallocate memory for RXP MPM group ids");
                }
                memset(&g_rxp_mpm_ids[old_capacity], 0, (g_rxp_mpm_ids_capa - old_capacity) * sizeof(g_rxp_mpm_ids[0]));
            }
            g_rxp_mpm_ids[start] = true;
            SCLogConfig("MPM group id %u will be offloaded to RXP", start);
        }
    }
    
}


/**
 * \brief Initialize the RXP context.
 *
 * \param mpm_ctx       Mpm context.
 */
void SCRXPInitCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx_glob_id_cnt == 1) {
        // global init stage
        LoadMPM2RXPGroupIds();
    }

    if (mpm_ctx->ctx != NULL)
        return;

    mpm_ctx->ctx = SCCalloc(1, sizeof(SCRXPCtx));
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCRXPCtx);

    /* initialize the hash we use to speed up pattern insertions */
    SCRXPCtx *ctx = (SCRXPCtx *)mpm_ctx->ctx;
    ctx->init_hash = SCCalloc(INIT_HASH_SIZE, sizeof(SCRXPPattern *));
    if (ctx->init_hash == NULL) {
        exit(EXIT_FAILURE);
    }

    rte_atomic16_init(&g_wq_id);
    rte_atomic16_set(&g_wq_id, 0);

    struct rte_regexdev_info info;
    int res = rte_regexdev_info_get(0, &info);
    if (res != 0) {
        FatalError("Cannot get device info");
    }
    ctx->max_payload_size = info.max_payload_size;

    ctx->mpm_glob_id = mpm_ctx_glob_id_cnt++;
    if (g_rxp_mpm_ids_all || (g_rxp_mpm_ids && g_rxp_mpm_ids[ctx->mpm_glob_id])) {
        ctx->rxp_offloaded = true;
    } else {
        ctx->rxp_offloaded = false;
    }

    mpm_table[MPM_HS].InitCtx(&ctx->mpm_hs_ctx);
}

/**
 * \brief Destroy the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 */
void SCRXPDestroyThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    SCRXPPrintSearchStats(mpm_thread_ctx);
    // SCRXPCtx *ctx = (SCRXPCtx *)mpm_ctx->ctx;
    SCRXPThreadCtx *thr_ctx = (SCRXPThreadCtx *)mpm_thread_ctx->ctx;
    static thread_local bool printedout = false;
    if (!printedout) {
        SCLogNotice("RXP#%u searches:  %lu searched bytes: %lu "
                            "buffers: %lu uniq buffers: %lu "
                            "failed mbuf allocations: %lu failed enqueues: %lu", 
                            thr_ctx->qid, stats[thr_ctx->qid].g_rxp_searches, stats[thr_ctx->qid].g_rxp_searched_bytes, 
                            stats[thr_ctx->qid].g_rxp_buffers, stats[thr_ctx->qid].g_rxp_buffers_uniq, 
                            stats[thr_ctx->qid].g_rxp_failed_mp_gets, stats[thr_ctx->qid].g_rxp_failed_enqueues);
        SCLogNotice(" HS#%u searches:  %lu searched bytes:  %lu", thr_ctx->qid, stats[thr_ctx->qid].g_hs_searches, stats[thr_ctx->qid].g_hs_searched_bytes);
        printf("RESULT-thread-%u-rxp-searches %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_searches);
        printf("RESULT-thread-%u-rxp-searched-bytes %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_searched_bytes);
        printf("RESULT-thread-%u-rxp-buffers %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_buffers);
        printf("RESULT-thread-%u-rxp-buffers-uniq %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_buffers_uniq);
        printf("RESULT-thread-%u-rxp-failed-mp-gets %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_failed_mp_gets);
        printf("RESULT-thread-%u-rxp-no-packet %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_no_packet);
        printf("RESULT-thread-%u-rxp-failed-enqueues %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_failed_enqueues);
        printf("RESULT-thread-%u-rxp-skipped-enqueues %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_skipped_enqueues);
        printf("RESULT-thread-%u-rxp-error %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_error);
        printf("RESULT-thread-%u-rxp-timeout-error %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_timeout_error);
        printf("RESULT-thread-%u-rxp-max-match-error %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_max_match_error);
        printf("RESULT-thread-%u-rxp-max-prefix-error %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_max_prefix_error);
        printf("RESULT-thread-%u-rxp-max-limit-error %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_rxp_max_limit_error);

        printf("RESULT-thread-%u-hs-searches %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_hs_searches);
        printf("RESULT-thread-%u-hs-searched-bytes %lu\n", thr_ctx->qid, stats[thr_ctx->qid].g_hs_searched_bytes);
        printedout = true;
    }

    mpm_table[MPM_HS].DestroyThreadCtx(NULL, &thr_ctx->mpm_hs_thread_ctx);
}

/**
 * \brief Destroy the mpm context.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
void SCRXPDestroyCtx(MpmCtx *mpm_ctx)
{
    static bool freed = false;
    SCRXPCtx *ctx = (SCRXPCtx *)mpm_ctx->ctx;
    mpm_table[MPM_HS].DestroyCtx(&ctx->mpm_hs_ctx);

    if (!freed) {
        // nobody should be touching this arr after start so it is safe to free whenever
        SCFree(g_rxp_mpm_ids);
        g_rxp_mpm_ids = NULL;
    }

    if (g_rxp_op_mp != NULL) {
        rte_mempool_free(g_rxp_op_mp);
        g_rxp_op_mp = NULL;
    }

    if (g_pat_db.parray) {
        SCFree(g_pat_db.parray);
        g_pat_db.parray = NULL;
        g_pat_db.pattern_cnt = 0;
        g_pat_db.parray_capacity = 0;
    }

    if (ctx->init_hash) {
        SCRXPDestroyInitHash(mpm_ctx, ctx);
        ctx->init_hash = NULL;
    }

    SCFree(ctx);
    ctx = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCRXPCtx);
    return;
}

static inline struct rte_mbuf *
regex_create_segmented_mbuf(struct rte_mempool *mbuf_pool, int pkt_len,
		int nb_segs, void *buf) {

	struct rte_mbuf *m = NULL, *mbuf = NULL;
	char *src = buf;
	int data_len = 0;
	int i, size;
	int t_len;

	if (pkt_len < 1) {
		printf("Packet size must be 1 or more (is %d)\n", pkt_len);
		return NULL;
	}

	if (nb_segs < 1) {
		printf("Number of segments must be 1 or more (is %d)\n",
				nb_segs);
		return NULL;
	}

	t_len = pkt_len >= nb_segs ? (pkt_len / nb_segs +
				     !!(pkt_len % nb_segs)) : 1;
	size = pkt_len;

	/* Create chained mbuf_src and fill it with buf data */
	for (i = 0; size > 0; i++) {

		m = rte_pktmbuf_alloc(mbuf_pool);
		if (i == 0)
			mbuf = m;

		if (m == NULL) {
			printf("Cannot create segment for source mbuf");
			goto fail;
		}

		data_len = size > t_len ? t_len : size;
		memset(rte_pktmbuf_mtod(m, uint8_t *), 0,
				rte_pktmbuf_tailroom(m));
        m->ol_flags = m->ol_flags & ~(RTE_MBUF_F_INDIRECT|RTE_MBUF_F_EXTERNAL);
        rte_memcpy(rte_pktmbuf_mtod(m, uint8_t *), src, data_len);
        m->data_len = data_len;
        m->pkt_len = data_len;
		// memcpy(rte_pktmbuf_mtod(m, uint8_t *), src, data_len);
		// dst = (uint8_t *)rte_pktmbuf_append(m, data_len);
		// if (dst == NULL) {
		// 	printf("Cannot append %d bytes to the mbuf\n",
		// 			data_len);
		// 	goto fail;
		// }

		if (mbuf != m)
			rte_pktmbuf_chain(mbuf, m);
		src += data_len;
		size -= data_len;

	}
	return mbuf;

fail:
	if (mbuf)
		rte_pktmbuf_free(mbuf);
	return NULL;
}

static inline struct rte_mbuf *
regex_create_copy_mbuf(struct rte_mempool *mbuf_pool, int pkt_len,
		int nb_segs, void *buf) {

	struct rte_mbuf *m = NULL;
	char *src = buf;
	int data_len = 0;

	if (pkt_len < 1) {
		printf("Packet size must be 1 or more (is %d)\n", pkt_len);
		return NULL;
	}

	if (nb_segs < 1) {
		printf("Number of segments must be 1 or more (is %d)\n",
				nb_segs);
		return NULL;
	}

    m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL) {
        printf("Cannot create segment for source mbuf");
        goto fail;
    }

    // TODO IMMEDIATE: try to assign data as we assigned directly, 
    data_len = pkt_len;
    memset(rte_pktmbuf_mtod(m, uint8_t *), 0,
            rte_pktmbuf_tailroom(m));
    m->ol_flags = m->ol_flags & ~(RTE_MBUF_F_INDIRECT|RTE_MBUF_F_EXTERNAL);
    rte_memcpy(rte_pktmbuf_mtod(m, uint8_t *), src, data_len);
    m->data_len = data_len;
    m->pkt_len = data_len;
	return m;

fail:
	if (m)
		rte_pktmbuf_free(m);
	return NULL;
}

static inline struct rte_mbuf *
regex_create_mbuf_ext_buffer(struct rte_mempool *mbuf_pool, int pkt_len,
		int nb_segs, void *buf) {

	struct rte_mbuf *m = NULL;

	if (pkt_len < 1) {
		printf("Packet size must be 1 or more (is %d)\n", pkt_len);
		return NULL;
	}

	if (nb_segs < 1) {
		printf("Number of segments must be 1 or more (is %d)\n",
				nb_segs);
		return NULL;
	}

    m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL) {
        printf("Cannot create segment for source mbuf");
        goto fail;
    }

    // Set the data length and flags
    m->data_len = pkt_len;
    m->pkt_len = pkt_len;
    m->ol_flags |= RTE_MBUF_F_EXTERNAL;

    rte_iova_t iova = rte_mem_virt2iova(buf);
    if (iova == RTE_BAD_IOVA) {
        fprintf(stderr, "Failed to get IOVA of external buffer\n");
        goto fail;
    }
    rte_pktmbuf_attach_extbuf(
            m, buf, iova, pkt_len, &shinfo);

	return m;

fail:
	if (m)
		rte_pktmbuf_free(m);
	return NULL;
}

/**
 * \brief The RXP async search function.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * \param pmq            Pointer to the Pattern Matcher Queue to hold
 *                       search matches.
 * \param buf            Buffer to be searched.
 * \param buflen         Buffer length.
 *
 * \retval matches Match count.
 */
static inline uint32_t SCRXPSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen, Packet *p)
{
    uint32_t ret = 0;
    SCRXPCtx *rxp_ctx = (SCRXPCtx *)mpm_ctx->ctx;
    SCRXPThreadCtx *rxp_t_ctx = (SCRXPThreadCtx *)(mpm_thread_ctx->ctx);
    SCRXPOp *op = NULL;
    if (unlikely(buflen == 0)) {
        return 0;
    }

    uint32_t *jobs_inprogress = NULL; // can refer to either stream or TX-specific requests
    uint32_t *flow_jobs_inprogress = NULL;
    if (pmq == NULL && p) {
        pmq = &p->stream_data.pmq;
        jobs_inprogress = &p->stream_data.jobs_inprogress;

        if (p->flow) {
            flow_jobs_inprogress = &p->flow->rxp_async_ops;
        }
    } else if (pmq == NULL && p == NULL) {
        FatalError("both pmqs are null");
    } else {
        // if pmq is set we are getting called from somewhere it was not possible to bind to a packet/job
        stats[rxp_t_ctx->qid].g_rxp_no_packet++;
        goto hs_fallback;
    }

    if (suricata_ctl_flags & SURICATA_STOP)
        goto hs_fallback; // async operations wouldn't be read in shutdown phase
    
    uint16_t default_headroom_sz = (uint16_t)MIN((uint16_t)RTE_PKTMBUF_HEADROOM, (uint16_t)((struct rte_mbuf *)buf)->buf_len);
    if (rte_pktmbuf_headroom((struct rte_mbuf *)buf) == default_headroom_sz) {
        // we are getting a fresh mbuf, let's modify the data buffer offset to point into payload
        // struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod((struct rte_mbuf *)buf, struct rte_ether_hdr *);
        
        int hdr_len = p->payload - p->ext_pkt;
        if (hdr_len < 0) {
            FatalError("Invalid header length");
        }
        rte_pktmbuf_adj((struct rte_mbuf *)buf, hdr_len);
    }

    SCLogDebug("Buflen %d, min %d\n",buflen, rxp_t_ctx->rxp_minlength);
    if (buflen < rxp_t_ctx->rxp_minlength || !rxp_ctx->rxp_offloaded) {
        stats[rxp_t_ctx->qid].g_rxp_skipped_enqueues++;
        // relying on an assumption that SCRXPSearch is called either with PMQ set - and thus with regular buffers
        // or directly with MBUFs where we inspect only the payload
        buf = rte_pktmbuf_mtod((struct rte_mbuf *)buf, const uint8_t *);
        goto hs_fallback;
    }


    if ( rxp_t_ctx->jobs_inprogress  >= g_rxp_desc) {
        stats[rxp_t_ctx->qid].g_rxp_failed_enqueues++;
        // relying on an assumption that SCRXPSearch is called either with PMQ set - and thus with regular buffers
        // or directly with MBUFs where we inspect only the payload
        buf = rte_pktmbuf_mtod((struct rte_mbuf *)buf, const uint8_t *);
        goto hs_fallback;
    }

    if (p->rxp.inq != -1) {

        g_rxp_ops[p->rxp.inq]->group_id1 = rxp_ctx->mpm_glob_id;
        g_rxp_ops[p->rxp.inq]->req_flags |= RTE_REGEX_OPS_REQ_GROUP_ID1_VALID_F;
        op = (SCRXPOp*)g_rxp_ops[p->rxp.inq]->user_ptr;
        op->nb++;
        goto enqed;
    }

    // async object init
    ret = rte_mempool_get(g_rxp_op_mp, (void **)&op);
    if (ret != 0) {
        SCLogNotice("Failed to get RXP OP");
        // relying on an assumption that SCRXPSearch is called either with PMQ set - and thus with regular buffers
        // or directly with MBUFs where we inspect only the payload
        buf = rte_pktmbuf_mtod((struct rte_mbuf *)buf, const uint8_t *);
        stats[rxp_t_ctx->qid].g_rxp_failed_mp_gets++;
        goto hs_fallback;
    }
    op->mbuf = (struct rte_mbuf *)buf;
    op->tctx = rxp_t_ctx;
    op->p = p;
    op->nb = 1;
    op->mctx = rxp_ctx;
    rxp_t_ctx->jobs_inprogress++;
    int i = g_rxp_ops_idx;
    p->rxp.inq = i;
    g_rxp_ops[i]->user_ptr = op;
    g_rxp_ops[i]->mbuf = (struct rte_mbuf *)buf;
    // tx_offload is actually used as a cycle counter

    //g_rxp_ops[i]->mbuf->tx_offload = rte_rdtsc_precise();

    g_rxp_ops[i]->group_id0 = rxp_ctx->mpm_glob_id;
    g_rxp_ops[i]->req_flags = 0; // reset flags
    // todo: possibility to add single-match scanning (revisit if it works)
    // todo: more groups - more valid bits to set
    g_rxp_ops[i]->req_flags |= RTE_REGEX_OPS_REQ_GROUP_ID0_VALID_F;

    g_rxp_ops_idx++;
enqed:
    (*jobs_inprogress) += 1;

    if (flow_jobs_inprogress)
        (*flow_jobs_inprogress) += 1;

    
    return 0;

hs_fallback:
    stats[rxp_t_ctx->qid].g_hs_searches += 1;
    stats[rxp_t_ctx->qid].g_hs_searched_bytes += buflen;

    if (op) {
        rte_mempool_put(g_rxp_op_mp, op);
    }
    return mpm_table[MPM_HS].Search(&rxp_ctx->mpm_hs_ctx, &rxp_t_ctx->mpm_hs_thread_ctx, pmq, buf, buflen, NULL);
}

void rxp_flush_buffer(MpmThreadCtx *mpm_thread_ctx)
{
    SCRXPThreadCtx *rxp_t_ctx = (SCRXPThreadCtx *)(mpm_thread_ctx->ctx);

    uint16_t enqed = rte_regexdev_enqueue_burst(0, rxp_t_ctx->qid,
        g_rxp_ops, g_rxp_ops_idx);

    assert(enqed == g_rxp_ops_idx);
    g_rxp_ops_idx = 0;
    for (int i = 0; i < enqed; i++) {
        SCRXPOp* op = ((SCRXPOp*)g_rxp_ops[i]->user_ptr);
        Packet* p = op->p;
        p->rxp.async_in_progress = true;
        p->rxp.inq = 0;
        stats[rxp_t_ctx->qid].g_rxp_searches += op->nb;
        stats[rxp_t_ctx->qid].g_rxp_searched_bytes += rte_pktmbuf_data_len(g_rxp_ops[i]->mbuf);
        stats[rxp_t_ctx->qid].g_rxp_buffers++;
        if (g_rxp_ops[i]->mbuf != g_rxp_prev_scanned_buffer) {

            g_rxp_prev_scanned_buffer = g_rxp_ops[i]->mbuf ;
        }
    }
    if (g_rxp_minlength < 0) {
        //Too much jobs in queue and minlength is lower than 2048 (not completely deactivated already)
        if (rxp_t_ctx->jobs_inprogress >= rxp_t_ctx->max_jobs_threshold && rxp_t_ctx->rxp_minlength < 2048) {
            SCLogDebug("Queue %d, threshold++ %d, min %d, in progress %d", rxp_t_ctx->qid,rxp_t_ctx->max_jobs_threshold, rxp_t_ctx->rxp_minlength, rxp_t_ctx->jobs_inprogress );

            rxp_t_ctx->max_jobs_threshold = min(rxp_t_ctx->max_jobs_threshold + 16, g_rxp_desc - 8);
            rxp_t_ctx->rxp_minlength *= 2;

        }
    }
}



static inline void SCRXPConvertRXPOpToPmq(struct rte_regex_ops *o, PrefilterRuleStore *pmq) {
    if (unlikely(o->rsp_flags & (RTE_REGEX_OPS_RSP_MAX_SCAN_TIMEOUT_F | RTE_REGEX_OPS_RSP_MAX_MATCH_F | RTE_REGEX_OPS_RSP_MAX_PREFIX_F | RTE_REGEX_OPS_RSP_RESOURCE_LIMIT_REACHED_F))) {

        SCRXPOp *op = (SCRXPOp *)o->user_ptr;
        SCRXPThreadCtx* rxp_t_ctx = op->tctx;
    /*  if (o->nb_actual_matches == 0)
            SCLogError("Error without matches");*/
        stats[rxp_t_ctx->qid].g_rxp_error ++;
        if (o->rsp_flags & (RTE_REGEX_OPS_RSP_MAX_SCAN_TIMEOUT_F))
            stats[rxp_t_ctx->qid].g_rxp_timeout_error++;
        if (o->rsp_flags & (RTE_REGEX_OPS_RSP_MAX_MATCH_F))
            stats[rxp_t_ctx->qid].g_rxp_max_match_error++;
        if (o->rsp_flags & (RTE_REGEX_OPS_RSP_MAX_PREFIX_F))
            stats[rxp_t_ctx->qid].g_rxp_max_prefix_error++;
        if (o->rsp_flags & (RTE_REGEX_OPS_RSP_RESOURCE_LIMIT_REACHED_F))
            stats[rxp_t_ctx->qid].g_rxp_max_limit_error++;

        //Emergency fallback to HS
        char* buf = rte_pktmbuf_mtod(op->mbuf, const uint8_t *);
        SCRXPCtx *rxp_ctx = op->mctx;
        //SCLogNotice("Search %p %p buf %p len %d", &rxp_ctx->mpm_hs_ctx, &rxp_t_ctx->mpm_hs_thread_ctx, buf, op->mbuf->data_len);
        mpm_table[MPM_HS].Search(&rxp_ctx->mpm_hs_ctx, &rxp_t_ctx->mpm_hs_thread_ctx, pmq, buf, op->mbuf->data_len, NULL);
        return;
    }
    for (uint16_t match_i = 0; match_i < o->nb_actual_matches; match_i++) {
        if (o->rsp_flags != 0) {
            SCLogDebug("Matched with:");
            SCLogDebug("RTE_REGEX_OPS_RSP_PMI_SOJ_F: %s", o->rsp_flags & RTE_REGEX_OPS_RSP_PMI_SOJ_F ? "yes" : "no");
            SCLogDebug("RTE_REGEX_OPS_RSP_PMI_EOJ_F: %s", o->rsp_flags & RTE_REGEX_OPS_RSP_PMI_EOJ_F ? "yes" : "no");
            SCLogDebug("RTE_REGEX_OPS_RSP_MAX_SCAN_TIMEOUT_F: %s", o->rsp_flags & RTE_REGEX_OPS_RSP_MAX_SCAN_TIMEOUT_F ? "yes" : "no");
            SCLogDebug("RTE_REGEX_OPS_RSP_MAX_MATCH_F: %s", o->rsp_flags & RTE_REGEX_OPS_RSP_MAX_MATCH_F ? "yes" : "no");
            SCLogDebug("RTE_REGEX_OPS_RSP_MAX_PREFIX_F: %s", o->rsp_flags & RTE_REGEX_OPS_RSP_MAX_PREFIX_F ? "yes" : "no");
            SCLogDebug("RTE_REGEX_OPS_RSP_RESOURCE_LIMIT_REACHED_F: %s", o->rsp_flags & RTE_REGEX_OPS_RSP_RESOURCE_LIMIT_REACHED_F ? "yes" : "no");
        }
        // I need to convert this rule_id to the RXP Signature 
        struct rte_regexdev_match *m = &(o->matches[match_i]);
        SCLogDebug("MPM matched rule_id: %d", m->rule_id);
        SCLogDebug("MPM matched group_id: %d", m->group_id);
        SCLogDebug("MPM matched start_offset: %d", m->start_offset);
        SCLogDebug("MPM matched len: %d", m->len);

        if (m->rule_id > g_pat_db.parray_capacity) {
            // sometimes it throws out pattern id out of range  - tried to investigate but to no avail
            SCLogNotice("Rule_id %d is out of bounds", m->rule_id);
            continue;
        }
        if (!m->rule_id) {
            SCLogNotice("Rule_id not set");
            continue;
        }

        SCRXPPattern *pat = g_pat_db.parray[m->rule_id];
        if (!pat) {
            SCLogNotice("No pattern found for rule %d", m->rule_id);
            continue;
        }

        // SCLogInfo("Matched with rule_id: %d g_patdb %p arr %p p %p", m->rule_id, g_pat_db, g_pat_db.parray, p);
        // SCLogInfo("Rule_id: %d p %p psids %p psidsize %d", m->rule_id, p, p->sids, p->sids_size);
        PrefilterAddSids(pmq, pat->sids, pat->sids_size);
    }
}

/**
 * \brief Process the RXP results.
 * \param o [in] Pointer to the RXP operation.
 * \param p [out] Pointer to the retrieved packet
 */
void SCRXPProcessRegexOp(struct rte_regex_ops *o, Packet **p) {
    SCRXPOp *op = (SCRXPOp *)o->user_ptr;
    *p = op->p;

    SCRXPThreadCtx* rxp_t_ctx = op->tctx;
    int n_req = op->nb;
    //SCLogNotice("Received %d, now %d",n_req,rxp_t_ctx->jobs_inprogress);
    rxp_t_ctx->jobs_inprogress-=1;//One per buffer

    if (rxp_t_ctx->jobs_inprogress <= rxp_t_ctx->min_jobs_threshold) {
        SCLogDebug("Queue %d in progress %d", rxp_t_ctx->qid, rxp_t_ctx->jobs_inprogress );
        if (g_rxp_minlength < 0 && rxp_t_ctx->rxp_minlength > 1) {
            rxp_t_ctx->max_jobs_threshold = max(g_rxp_desc / 2, rxp_t_ctx->max_jobs_threshold - 16);
            rxp_t_ctx->rxp_minlength /= 2;
            SCLogDebug("Queue %d, threshold-- %d, min %d, in progress %d", rxp_t_ctx->qid,rxp_t_ctx->max_jobs_threshold, rxp_t_ctx->rxp_minlength, rxp_t_ctx->jobs_inprogress );
        }
    }

    SCRXPConvertRXPOpToPmq(o, &((*p)->stream_data.pmq));


    (*p)->stream_data.jobs_inprogress-= n_req;
    if ((*p)->flow) {
        (*p)->flow->rxp_async_ops-=n_req;
    }

    op->mbuf = NULL;
    rte_mempool_put(g_rxp_op_mp, op);
}

/**
 * \brief Add a case insensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patlen  The pattern length.
 * \param offset  The pattern offset.
 * \param depth   The pattern depth.
 * \param pid     The pattern id.
 * \param sid     The pattern signature id.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCRXPAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     SigIntId sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    mpm_table[MPM_HS].AddPatternNocase(&(((SCRXPCtx *)mpm_ctx->ctx)->mpm_hs_ctx), pat, patlen, offset, depth, pid, sid, flags);
    return SCRXPAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

/**
 * \brief Add a case sensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patlen  The pattern length.
 * \param offset  The pattern offset.
 * \param depth   The pattern depth.
 * \param pid     The pattern id.
 * \param sid     The pattern signature id.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCRXPAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     SigIntId sid, uint8_t flags)
{
    mpm_table[MPM_HS].AddPattern(&((SCRXPCtx *)mpm_ctx->ctx)->mpm_hs_ctx, pat, patlen, offset, depth, pid, sid, flags);
    return SCRXPAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

void SCRXPPrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{
    mpm_table[MPM_HS].PrintThreadCtx(&((SCRXPThreadCtx *)mpm_thread_ctx->ctx)->mpm_hs_thread_ctx);
    return;
}

void SCRXPPrintInfo(MpmCtx *mpm_ctx)
{
    mpm_table[MPM_HS].PrintCtx(&((SCRXPCtx *)mpm_ctx->ctx)->mpm_hs_ctx);
    return;
}

/************************** Mpm Registration ***************************/

/**
 * \brief Register the Hyperscan MPM.
 */
void MpmRXPRegister(void)
{
    mpm_table[MPM_RXP].name = "rxp";
    mpm_table[MPM_RXP].InitCtx = SCRXPInitCtx;
    mpm_table[MPM_RXP].InitThreadCtx = SCRXPInitThreadCtx;
    mpm_table[MPM_RXP].DestroyCtx = SCRXPDestroyCtx;
    mpm_table[MPM_RXP].DestroyThreadCtx = SCRXPDestroyThreadCtx;
    mpm_table[MPM_RXP].AddPattern = SCRXPAddPatternCS;
    mpm_table[MPM_RXP].AddPatternNocase = SCRXPAddPatternCI;
    mpm_table[MPM_RXP].Prepare = SCRXPPreparePatterns;
    mpm_table[MPM_RXP].Search = SCRXPSearch;
    mpm_table[MPM_RXP].PrintCtx = SCRXPPrintInfo;
    mpm_table[MPM_RXP].PrintThreadCtx = SCRXPPrintSearchStats;
#ifdef UNITTESTS
    mpm_table[MPM_RXP].RegisterUnittests = SCRXPRegisterTests;
#endif
    mpm_table[MPM_RXP].feature_flags = MPM_FEATURE_FLAG_DEPTH | MPM_FEATURE_FLAG_OFFSET;
    /* Set Hyperscan memory allocators */
    // SCRXPSetAllocators();
}

static int FileToMD5(const char *filename, uint8_t **md5_digest_out,
                       uint32_t *md5_digest_len_out) {
  FILE *file;
  file = fopen(filename, "r");
  if (!file) {
    SCLogDebug("Failed to open file: %s", filename);
    return -1;
  }

  EVP_MD_CTX *mdctx;
  uint8_t *md5_digest;
  uint32_t md5_digest_len = EVP_MD_size(EVP_md5());

  // MD5_Init
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

  // MD5_Update
  int32_t bytes;
  uint8_t data[1024];
  while ((bytes = fread(data, 1, 1024, file)) != 0)
    EVP_DigestUpdate(mdctx, data, bytes);

  // MD5_Final
  md5_digest = (uint8_t *)OPENSSL_malloc(md5_digest_len);
  EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
  EVP_MD_CTX_free(mdctx);

  *md5_digest_out = md5_digest;
  *md5_digest_len_out = md5_digest_len;

  fclose(file);
  return 0;
}

static const char *RXPCCacheConstructFPath(uint8_t *hash_arr,
                                         uint32_t hash_arr_len) {
  static char hash_file[2048];
  if (hash_arr_len * 2 + 255 > 2048)
    FatalError("Hash array length too long");
  char hash_file_path_prefix_path[] = "/tmp/";
  char hash_file_path_suffix[] = "_v1.rof2.bin";
  uint16_t hash_file_bytes_written = 0;
  snprintf(hash_file, sizeof(hash_file), "%s", hash_file_path_prefix_path);
  hash_file_bytes_written += sizeof(hash_file_path_prefix_path) - 1;
  for (uint32_t i = 0; i < hash_arr_len; i++) {
    snprintf(hash_file + hash_file_bytes_written,
             sizeof(hash_file) - hash_file_bytes_written, "%02x", hash_arr[i]);
    hash_file_bytes_written += 2;
  }
  snprintf(hash_file + hash_file_bytes_written,
           sizeof(hash_file) - hash_file_bytes_written, "%s", hash_file_path_suffix);
  hash_file_bytes_written += sizeof(hash_file_path_suffix) - 1;
  return hash_file;
}

static int RXPCLoadCache(const char *filename) {
  uint8_t *md5_digest;
  uint32_t md5_digest_len;
  if (FileToMD5(filename, &md5_digest, &md5_digest_len) != 0) {
    FatalError("Failed to compute MD5 hash");
  }

  const char *hash_file_static =
      RXPCCacheConstructFPath(md5_digest, md5_digest_len);
  SCLogInfo("Trying to use cached RXPC ROF2 at %s", hash_file_static);
  FILE *db_cache = fopen(hash_file_static, "r");
  if (db_cache) {
    fclose(db_cache);
    // cp the cached file to the default location from where it will be loaded
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "cp %s %s", hash_file_static, MPM_RXP_RXPC_OUTPUT_PREFIX_PATH ".rof2.binary");
    SCLogInfo("Copying cached RXPC ROF2 to %s", MPM_RXP_RXPC_OUTPUT_PREFIX_PATH ".rof2.binary");
    int status = system(cmd);
    if (status != 0) {
        FatalError("Failed to copy cached RXPC ROF2");
    }
    return 0;
  }
  return -1;
}

static int RXPCSaveCache(const char *filename) {
    uint8_t *md5_digest;
    uint32_t md5_digest_len;
    if (FileToMD5(filename, &md5_digest, &md5_digest_len) != 0) {
        FatalError("Failed to compute MD5 hash");
    }

    const char *hash_file_static =
        RXPCCacheConstructFPath(md5_digest, md5_digest_len);
    SCLogInfo("Caching the compiled RXPC ROF2 at %s", hash_file_static);
    // cp the cached file to the default location from where it will be loaded
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "cp %s %s", MPM_RXP_RXPC_OUTPUT_PREFIX_PATH ".rof2.binary", hash_file_static);
    SCLogInfo("Cacheing RXPC ROF2 to %s", hash_file_static);
    int status = system(cmd);
    if (status != 0) {
        SCLogWarning("Failed to cache the compiled RXPC ROF2");
    }
    return 0;
}

void RXPCompileRules(const char *sigfile) 
{
    if (rte_regexdev_count() == 0)
        return;

    if (RXPCLoadCache(MPM_RXP_PATTERNS_PATH) == 0)
        return;

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "rxpc -f %s -o %s", MPM_RXP_PATTERNS_PATH, MPM_RXP_RXPC_OUTPUT_PREFIX_PATH);
    SCLogInfo("Compiling all MPM patterns with command: %s", cmd);
    int status = system(cmd);
    if (status != 0) {
        FatalError("Failed to compile RXP rules");
    }
    RXPCSaveCache(MPM_RXP_PATTERNS_PATH);
}

void RXPInit()
{
    // regex configure start
    uint16_t num_devs;
    char *rules = NULL;
    long rules_len;
    struct rte_regexdev_info info;
    struct rte_regexdev_config dev_conf = { 0 };
    
    struct rte_regexdev_qp_conf qp_conf = {
        .nb_desc = MPM_RXP_DEFAULT_DESCRIPTORS,
        .qp_conf_flags = 0,
        .cb = NULL,
    };
    int res = 0;

    const char dpdk_node_query[] = "dpdk.interfaces";
    ConfNode *dpdk_node = ConfGetNode(dpdk_node_query);
    if (dpdk_node == NULL) {
        FatalError("Unable to get %s configuration node", dpdk_node_query);
    }
    int32_t entry_int;
    uint32_t entry_uint;
    ConfNode *if_node = ConfNodeLookupKeyValue(dpdk_node, "interface", RXPGetIfaceNameOfRXP(0));
    if (if_node == NULL) {
        FatalError("Unable to get interface configuration node");
    }
    const char *entry_str = NULL;
    int retval = ConfGetChildValue(if_node, "threads", &entry_str);
    if (retval < 0)
        FatalError("Unable to get threads configuration node");
    if (StringParseInt32(&entry_int, 10, 0, entry_str) < 0) {
        FatalError("Unable to parse threads configuration node");
    }
    if (entry_int < 1) {
        FatalError("Invalid threads configuration node");
    }
    int nb_worker_cores = (uint16_t)entry_int;

    retval = ConfGetChildValue(if_node, "rxp-min-buflen", &entry_str);
    if (retval < 0)
        FatalError("Unable to get rxp-min-buflen configuration node");
    if (StringParseInt32(&entry_int, 10, 0, entry_str) < 0) {
        FatalError("Unable to parse rxp-min-buflen configuration node");
    }
    g_rxp_minlength = entry_int;

    retval = ConfGetChildValue(if_node, "rxp-desc", &entry_str);
    if (retval < 0) {
        g_rxp_desc = MPM_RXP_DEFAULT_DESCRIPTORS;
        //FatalError("Unable to get rxp-desc configuration node");
    } else {
        if (StringParseUint32(&entry_uint, 10, 0, entry_str) < 0) {
            FatalError("Unable to parse rxp-desc configuration node");
        }
        g_rxp_desc = entry_uint;
    }
    qp_conf.nb_desc = g_rxp_desc;


    retval = ConfGetChildValue(if_node, "rxp-desc-max", &entry_str);
    if (retval < 0) {
        g_rxp_desc_max = MPM_RXP_DEFAULT_DESCRIPTORS * 16;
        //FatalError("Unable to get rxp-desc configuration node");
    } else {
        if (StringParseUint32(&entry_uint, 10, 0, entry_str) < 0) {
            FatalError("Unable to parse g_rxp_desc_max configuration node");
        }
        g_rxp_desc_max = entry_uint;
    }

    while (qp_conf.nb_desc * nb_worker_cores > g_rxp_desc_max)
        qp_conf.nb_desc /= 2;

    g_rxp_desc = qp_conf.nb_desc;

    num_devs = rte_regexdev_count();
    if (num_devs == 0) {
        FatalError("Error, no DPDK RXP devices detected");
    }

    rules_len = read_file(MPM_RXP_RULES_PATH, &rules);
    if (rules_len < 0) {
        res = -EIO;
        rte_free(rules);
        FatalError("Cannot read rules file of MPM patterns");
    }

    if (num_devs > 1) {
        FatalError("Error, only one rxp device supported at the moment");
    }

    for (int id = 0; id < num_devs; id++) {
        res = rte_regexdev_info_get(id, &info);
        if (res != 0) {
            rte_free(rules);
            rte_exit(EXIT_FAILURE, "Cannot get device info\n");
        }
        
        // SCLogNotice("RXP MPM matcher: device: %s dev_id: %d driver: %s", info.dev ? rte_dev_name(info.dev) : "unknown", id, info.driver_name ? info.driver_name : "unknown");
        SCLogInfo("RXP: max matches: %d max payload sz: %d max groups: %d max rules per group: %d max queues: %d max_chained_mbufs: %d",
                info.max_matches, info.max_payload_size, info.max_groups, info.max_rules_per_group, info.max_queue_pairs, info.max_segs);

        SCLogInfo("RXP: device capability RTE_REGEXDEV_CAPA_RUNTIME_COMPILATION_F: %ssupported", info.regexdev_capa & RTE_REGEXDEV_CAPA_RUNTIME_COMPILATION_F ? "" : "un");
        SCLogInfo("RXP: device capability RTE_REGEXDEV_CAPA_SUPP_PCRE_START_ANCHOR_F: %ssupported", info.regexdev_capa & RTE_REGEXDEV_CAPA_SUPP_PCRE_START_ANCHOR_F ? "" : "un");
        SCLogInfo("RXP: device capability RTE_REGEXDEV_CAPA_SUPP_PCRE_ATOMIC_GROUPING_F: %ssupported", info.regexdev_capa & RTE_REGEXDEV_CAPA_SUPP_PCRE_ATOMIC_GROUPING_F ? "" : "un");
        SCLogInfo("RXP: device capability RTE_REGEXDEV_CAPA_QUEUE_PAIR_OOS_F: %ssupported", info.regexdev_capa & RTE_REGEXDEV_CAPA_QUEUE_PAIR_OOS_F ? "" : "un");

        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_ALLOW_EMPTY_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_ALLOW_EMPTY_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_ANCHORED_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_ANCHORED_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_CASELESS_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_CASELESS_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_DOTALL_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_DOTALL_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_DUPNAMES_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_DUPNAMES_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_EXTENDED_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_EXTENDED_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_MATCH_UNSET_BACKREF_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_MATCH_UNSET_BACKREF_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_MULTILINE_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_MULTILINE_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_NEVER_BACKSLASH_C_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_NEVER_BACKSLASH_C_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_NO_AUTO_CAPTURE_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_NO_AUTO_CAPTURE_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_UCP_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_UCP_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_UNGREEDY_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_UNGREEDY_F ? "" : "un");
        SCLogInfo("RXP: rule capability RTE_REGEX_PCRE_RULE_UTF_F: %ssupported", info.rule_flags & RTE_REGEX_PCRE_RULE_UTF_F ? "" : "un");
        
        // todo: evaluate if this is useful
        // if (info.regexdev_capa & RTE_REGEXDEV_SUPP_MATCH_AS_END_F)
        //     dev_conf.dev_cfg_flags |= RTE_REGEXDEV_CFG_MATCH_AS_END_F;

        dev_conf.nb_queue_pairs = nb_worker_cores;
        dev_conf.nb_groups = g_mpm_groups_cnt;
        SCLogNotice("nb queues %u nb groups %u", nb_worker_cores, g_mpm_groups_cnt);
        dev_conf.nb_max_matches =
            info.max_matches; // BF doesn't support changing this value - too bad,
                                // it takes precious space - tested on BF2
        dev_conf.nb_rules_per_group = info.max_rules_per_group;
        dev_conf.rule_db_len = rules_len;
        dev_conf.rule_db = rules;
        res = rte_regexdev_configure(id, &dev_conf);
        if (res < 0) {
            rte_free(rules);
            FatalError("Error, can't configure device %d", id);
        }
        if (info.regexdev_capa & RTE_REGEXDEV_CAPA_QUEUE_PAIR_OOS_F) {
            SCLogInfo(
                    "Configuring out-of-order queue pairs for device %d", id);
            qp_conf.qp_conf_flags |= RTE_REGEX_QUEUE_PAIR_CFG_OOS_F;
        }

        for (int qp_id = 0; qp_id < nb_worker_cores; qp_id++) {
            res = rte_regexdev_queue_pair_setup(id, qp_id, &qp_conf);
            if (res < 0) {
                rte_free(rules);
                FatalError(
                        "Error, can't setup queue pair %u for device %s.\n", qp_id,
                        rte_dev_name(info.dev));
            }
        }

        res = rte_regexdev_start(id);
        if (res < 0) {
            FatalError("Cannot start regexdev %d - %s", id, rte_strerror(-res));
        }
    }
    rte_free(rules);
}

/**
 * \brief Clean up global memory used by all Hyperscan MPM instances.
 *
 * Currently, this is just the global scratch prototype.
 */
void MpmRXPGlobalCleanup(void)
{
    // SCMutexLock(&g_scratch_proto_mutex);
    // if (g_scratch_proto) {
    //     SCLogDebug("Cleaning up Hyperscan global scratch");
    //     hs_free_scratch(g_scratch_proto);
    //     g_scratch_proto = NULL;
    // }
    // SCMutexUnlock(&g_scratch_proto_mutex);

    // SCMutexLock(&g_db_table_mutex);
    // if (g_db_table != NULL) {
    //     SCLogDebug("Clearing Hyperscan database cache");
    //     HashTableFree(g_db_table);
    //     g_db_table = NULL;
    // }
    // SCMutexUnlock(&g_db_table_mutex);
}

