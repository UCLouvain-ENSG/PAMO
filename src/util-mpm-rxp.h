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

#ifndef SURICATA_UTIL_MPM_RXP__H
#define SURICATA_UTIL_MPM_RXP__H

#include <rte_atomic.h>
#include "detect-engine-prefilter.h"
#include "decode.h"

#define MPM_RXP_OPERATIONS 32 // number of operations when de/enqueueing to RXP queues

#define HAVE_RXP_TRACK_FLOW 1

extern thread_local int g_rxp_ops_idx;

struct regex_conf {
    uint32_t nb_qps;
    uint16_t qp_id_base;
    struct rte_regex_ops **ops;
//   struct regex_stats_burst *stats;
};

typedef struct SCRXPPattern_ {
    /* length of the pattern */
    uint16_t len;
    /* flags describing the pattern */
    uint8_t flags;
    /* holds the original pattern that was added */
    uint8_t *original_pat;
    /* pattern id */
    uint32_t id;
    /* pattern global id */
    uint32_t glob_pattern_id;

    uint16_t offset;
    uint16_t depth;

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;

    /* only used at ctx init time, when this structure is part of a hash
     * table. */
    struct SCRXPPattern_ *next;
} SCRXPPattern;

typedef struct SCRXPCtx_ {
    /* hash table used during ctx initialization to store and filter out the duplicities */
    SCRXPPattern **init_hash;
    bool rxp_offloaded;
    uint32_t mpm_glob_id;
    uint16_t max_payload_size;
    MpmCtx mpm_hs_ctx;
} SCRXPCtx;

typedef struct SCRXPThreadCtx_ {
    uint16_t qid;
    uint16_t min_buf_length;
    uint16_t rxp_minlength;
    uint16_t jobs_inprogress;
    uint16_t max_jobs_threshold;
    uint16_t min_jobs_threshold;
    struct rte_regex_ops **ops; // a helper structure, MLX copies contents of it to BF-specific ops before transmitting those to the HW
    MpmThreadCtx mpm_hs_thread_ctx; //Parent
} SCRXPThreadCtx;

typedef struct SCRXPOp_ {
    // likely
    // Det engine, de engine, flow, sgh, packet
    struct rte_mbuf *mbuf;
    Packet *p;
    SCRXPThreadCtx* tctx;
    SCRXPCtx *mctx;
    int nb;
} SCRXPOp;

void rxp_flush_buffer(MpmThreadCtx *mpm_thread_ctx);

void MpmRXPRegister(void);
void RXPCompileRules(const char *sigfile);
struct rte_regex_ops **RXPOpsAlloc(uint16_t ops_cnt, u_int16_t max_matches_cnt);
void SCRXPProcessRegexOp(struct rte_regex_ops *o, Packet **p);
void RXPInit(void);
void MpmRXPGlobalCleanup(void);

#endif /* SURICATA_UTIL_MPM_RXP__H */
