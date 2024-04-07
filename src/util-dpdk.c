/* Copyright (C) 2021 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 */

#include "suricata.h"
#include "util-dpdk.h"
#include "util-debug.h"
#include "util-byte.h"


#include <rte_flow.h>
struct rte_flow* _flows[3];
int flow_epoch = 0;
int _table[4096]; //max
int table_size;
int n_queues;
struct rte_eth_rss_conf _rss_conf;
bool init = 0;
int _last = 0;
int _use_group = 0;

bool update_reta_flow(int port_id, bool validate);


struct rte_flow* flow_add_redirect(int port_id, int from, int to, bool validate, int priority) {

    struct rte_flow_attr attr = {0};
    attr.ingress = 1;
    attr.group = from;
    attr.priority =  priority;

    struct rte_flow_action action[2] = {0};
    struct rte_flow_action_jump jump = {0};


    action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    action[0].conf = &jump;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;
    jump.group=to;

    struct rte_flow_item pattern[2] = {0};
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].spec = 0;
    pattern[0].mask = 0;
    pattern[0].last = 0;


    pattern[1].type =  RTE_FLOW_ITEM_TYPE_END;


    struct rte_flow_error error;
    int res = 0;
    if (validate)
        res = rte_flow_validate(port_id, &attr, pattern, action, &error);
    if (res == 0) {

        struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, action, &error);
        if (flow)
            SCLogNotice("Redirect from %d to %d success",from,to);
        else
            SCLogError("Could not add redirect from %d to %d, error %d : %s",from,to, res, error.message);
        return flow;
    } else {
        if (validate) {
            SCLogNotice("Rule did not validate : %d %d %d %d %s", res, from, to, priority, error.message);
        }
        return 0;
    }
}


void DPDKInitBalancer(void)
{
    struct rte_eth_dev_info dev_info;
    int err = rte_eth_dev_info_get(0, &dev_info);
    if (err != 0) {
        SCLogError("Failed to get device info for port 0: %s", rte_strerror(-err));
        return;
    }
    table_size = dev_info.reta_size;
    n_queues = dev_info.nb_rx_queues;
    for (int i = 0; i < table_size; i++) {
        _table[i] = i % n_queues;
    }

    if (rte_eth_dev_rss_hash_conf_get(0, &_rss_conf) < 0) {
        SCLogError("Failed to get RSS configuration for port 0");
        return;
    }



    SCLogNotice("Balancer init, %d %d", table_size, n_queues);

    if (_use_group) {
        SCLogNotice("Checking group support, redirect from 0 to 1");
        if (flow_add_redirect(0, 1,2, false, 0) != 0)
        {
            SCLogNotice("Using flow groups !");
        }
        else
        {
            SCLogNotice("Flow groups could not be created!");
        }
    }

    update_reta_flow(0, false);
    init = 1;

}

void DPDKCleanupEAL(void)
{
#ifdef HAVE_DPDK
    if (run_mode == RUNMODE_DPDK) {
        int retval = rte_eal_cleanup();
        if (retval != 0)
            SCLogError("EAL cleanup failed: %s", strerror(-retval));
    }
#endif
}

void DPDKCloseDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
#ifdef HAVE_DPDK
    if (run_mode == RUNMODE_DPDK) {
        uint16_t port_id;
        int retval = rte_eth_dev_get_port_by_name(ldev->dev, &port_id);
        if (retval < 0) {
            SCLogError("%s: failed get port id, error: %s", ldev->dev, rte_strerror(-retval));
            return;
        }

        SCLogPerf("%s: closing device", ldev->dev);
        rte_eth_dev_close(port_id);
    }
#endif
}

void DPDKFreeDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
#ifdef HAVE_DPDK
    if (run_mode == RUNMODE_DPDK) {
        SCLogNotice("%s: releasing packet mempool", ldev->dev);
        for (int32_t i = 0; i < DPDK_MAX_THREADS; i++) {
            if (ldev->dpdk_vars.pkt_mp[i] != 0) {
                rte_mempool_free(ldev->dpdk_vars.pkt_mp[i]);
            }
        }
    }
#endif
}

#ifdef HAVE_DPDK
/**
 * Retrieves name of the port from port id
 * Not thread-safe
 * @param pid
 * @return static dev_name on success
 */
const char *DPDKGetPortNameByPortID(uint16_t pid)
{
    static char dev_name[RTE_ETH_NAME_MAX_LEN];
    int32_t ret = rte_eth_dev_get_name_by_port(pid, dev_name);
    if (ret < 0) {
        FatalError("Port %d: Failed to obtain port name (err: %s)", pid, rte_strerror(-ret));
    }
    return dev_name;
}

int base = 2;
bool update_reta_flow(int port_id, bool validate) {
    int _use_mark = 0;
again:

    struct rte_flow_error error;

    /**
     * If groups are supported, we use 3 tables.
     The first one to redirect to 2 and 3 so we can slowly update 3, then make the first one go to 3, then do the opposite, etc.
     */

     if (_use_group) {

        struct rte_flow* old = _flows[ 1 + (flow_epoch % 2)];
        if (old) {
            rte_flow_destroy(port_id, old, &error);
        }
    }

    struct rte_flow_attr attr = {0};
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    if (_use_group) {
        attr.group = base + (flow_epoch % 2);
        attr.priority = 0;
    } else {
        attr.group = 0;
        attr.priority = (flow_epoch % 2);
    }


    struct rte_flow_action action[3] = {0};
    struct rte_flow_action_mark mark = {0};
    struct rte_flow_action_rss rss = {0};

    memset(action, 0, sizeof(action));
    memset(&rss, 0, sizeof(rss));

    int aid = 0;
    if (_use_mark) {
        action[0].type = RTE_FLOW_ACTION_TYPE_MARK;
        mark.id = flow_epoch;
        action[0].conf = &mark;
        ++aid;
    }

    action[aid].type = RTE_FLOW_ACTION_TYPE_RSS;
    assert(table_size > 0);
    uint16_t queue[table_size];
    for (int i = 0; i < table_size; i++) {
        queue[i] = _table[i];
        assert(_table[i] >= 0);
        //SCLogNotice("%d->%d",i,_table[i]);
    }
    rss.types = _rss_conf.rss_hf;
    rss.key_len = _rss_conf.rss_key_len;
    rss.queue_num = table_size;
    rss.key = _rss_conf.rss_key;
    rss.queue = queue;
    rss.level = 0;
    rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
    action[aid].conf = &rss;
    ++aid;
    action[aid].type = RTE_FLOW_ACTION_TYPE_END;
    ++aid;

    struct rte_flow_item patterns[3] = {0};
    //Ethernet


    patterns[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    //struct rte_flow_item_eth eth = {0}; not needed if 0 normally
    patterns[0].spec = 0;
    patterns[0].mask = 0;
    patterns[0].last = 0;

    patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV4;

    patterns[1].spec = 0;
    patterns[1].mask = 0;

    patterns[1].last = 0;


    patterns[2].type =  RTE_FLOW_ITEM_TYPE_END;

    int res = 0;
    SCLogNotice("Validating flow %d %d %d %d. %p %p %p", port_id, attr.group, _use_mark, validate, &attr, patterns, action);
    //res = rte_flow_validate(port_id, &attr, patterns, action, &error);
/*
    if (_use_mark && res) {
        SCLogNotice("Rule did not validate with mark. Trying again without mark. Error %d (DPDK errno %d : %s",res,rte_errno, rte_strerror(rte_errno));
        _use_mark = 0;
        goto again;
    }
 */
    if (!res) {

        struct rte_flow *flow = rte_flow_create(port_id, &attr, patterns, action, &error);


        if (flow) {
            struct rte_flow* r1;
            SCLogNotice("Flow added successfully!");

            struct rte_flow* old = flow;
            if (_use_group)
                r1 = flow_add_redirect(port_id, 1, base + (flow_epoch % 2), false, flow_epoch % 2);
            if (_flows[0])
                rte_flow_destroy(port_id,_flows[0],&error);
            if (_use_group)
                _flows[0] = r1;
            else
                _flows[0] = flow;
        } else {
                SCLogNotice("Could not add pattern, error %d %d : %s",  res,rte_errno, error.message);
        }

    }
    flow_epoch ++;



}

#include <rte_ethdev.h>
#define MAX_QUEUES 128

void DPDKLoadBalance() {

    static uint64_t prev_queue_stats[MAX_QUEUES] = {0};

    struct rte_eth_stats stats;
    uint64_t queue_diffs[MAX_QUEUES] = {0};
    uint16_t max_queue = 0, min_queue = 0;
    uint64_t max_diff = 0, min_diff = UINT64_MAX;

    // Get the current stats
    if (rte_eth_stats_get(0, &stats) < 0) {
        SCLogError("Failed to get stats for port 0");
        return;
    }

        uint64_t mean = 0;
    // Compute the difference since the last call
    for (uint16_t i = 0; i < n_queues; i++) {
        uint64_t current = stats.q_ipackets[i];
        queue_diffs[i] = current - prev_queue_stats[i];
        SCLogNotice("Queue %d: %lu", i, queue_diffs[i]);
        prev_queue_stats[i] = current;
        mean+=queue_diffs[i];
        // Track the queue with the most and least packets
        if (queue_diffs[i] > max_diff) {
            max_diff = queue_diffs[i];
            max_queue = i;
        }
        if (queue_diffs[i] < min_diff) {
            min_diff = queue_diffs[i];
            min_queue = i;
        }
    }
    if (!init) {
        SCLogError("Balancer not initialized");
        return;
    }

    if (max_queue == min_queue) {
        SCLogNotice("All queues are balanced");
        return;
    }
    mean /= n_queues;
    if (mean < 1000) {
        SCLogNotice("Traffic is too low, not rebalancing");
        return;
    }

    if (queue_diffs[max_queue] < mean*1.1) {
        SCLogNotice("Imbalance is not too bad, mean %d, max %d, not rebalancing", mean, queue_diffs[max_queue]);
        return;
    }

    bool changed = false;

    // Rebalance queues
    for (uint16_t i = 0; i < table_size; i++) {
        int j = (i + _last) % table_size;
        if (_table[j] == max_queue) {
            _table[j] = min_queue;
            SCLogNotice("Rebalancing: Moved queue %d to %d at index %d", max_queue, min_queue, j);
            changed = true;
            _last = j + 1;
            break;
        }
    }

    if (changed)
        update_reta_flow(0, false);
}


#endif /* HAVE_DPDK */
