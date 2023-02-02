#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>
#include "maps.h"
#include "helpers.h"

#define DEBUG

#ifdef DEBUG
#define debug(fmt, ...) bpf_printk("tc_main: " fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...) do{}while(0)
#endif

#define error(fmt, ...) bpf_printk("BUG: tc_main: " fmt, ##__VA_ARGS__)

#define NS_PER_MS 1000000

static inline int set_delay(struct __sk_buff *skb, uint32_t *delay_ms) {
    uint64_t delay_ns;
    uint64_t now = bpf_ktime_get_ns();
    delay_ns = (*delay_ms) * NS_PER_MS;
    uint64_t ts = skb->tstamp;
    uint64_t new_ts = ((uint64_t)skb->tstamp) + delay_ns;

    // debug msgs, read with
    // sudo cat /sys/kernel/debug/tracing/trace_pipe
    //const char fmt_ts[] = "skb Tstamp: %d\n";
    //bpf_trace_printk(fmt_ts, sizeof(fmt_ts), ts);
    //const char fmt_str[] = "NOW Tstamp: %d\n";
    //bpf_trace_printk(fmt_str, sizeof(fmt_str), now);
    //const char fmt_str2[] = "Now + delay Tstamp: %d\n";
    //bpf_trace_printk(fmt_str2, sizeof(fmt_str2), now + delay_ns);
    //const char fmt_str3[] = "New Tstamp: %d\n";
    //bpf_trace_printk(fmt_str3, sizeof(fmt_str3), new_ts);

    // check if skb->tstamp == 0
    if (!ts) {
        skb->tstamp = now + delay_ns;
        return TC_ACT_OK;
    }
    skb->tstamp = new_ts;

    return TC_ACT_OK;
}

static inline int tc_main(struct __sk_buff *skb)
{
    void * data, * data_end;
    struct hdr_cursor nh;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    struct udphdr *uhdr;
    struct vxlanhdr *vhdr;
    int eth_type, ip_type, udp_port, vni;

    // data is a void* to the beginning of the packet
    data = (void *)(unsigned long long)skb->data;

    // data_end is a void* to the end of the packet
    data_end = (void *)(unsigned long long)skb->data_end;

    // nh keeps track of the beginning of the next header to parse
    nh.pos = data;

    // parse ethernet
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type != bpf_htons(ETH_P_IP)) {
        debug("not an IP packet");
        return TC_ACT_OK;
    }

    // parse IPv4
    ip_type = parse_iphdr(&nh, data_end, &iphdr);
    if (ip_type != IPPROTO_UDP) {
        debug("not a UDP packet");
        return TC_ACT_OK;
    }

    // parse UDP header
    if (parse_udphdr(&nh, data_end, &uhdr) < 0) {
        error("failed to parse UDP header");
        return TC_ACT_OK;
    }

    // check for VXLAN port 4789
    udp_port = bpf_ntohs(uhdr->dest);
    if (udp_port != 4789) {
        debug("not a VXLAN packet");
        return TC_ACT_OK;
    }

    // parse VXLAN header
    if (parse_vxlanhdr(&nh, data_end, &vhdr) < 0) {
        error("failed to parse VXLAN packet");
        return TC_ACT_OK;
    }

    vni = vxlanhdr_vni(vhdr);
    debug("found vxlan pkt with vni:%d", vni);

    if (vni == 102 || vni == 101) {
        uint32_t delayms=100;
        return set_delay(skb, &delayms);
    } else {
        return TC_ACT_OK;
    }
}

SEC("tc")
int tc_main_ingress(struct __sk_buff *skb)
{
    debug("tc_main_ingress");
    return tc_main(skb);
}

SEC("tc")
int tc_main_egress(struct __sk_buff *skb)
{
    debug("tc_main_egress");
    return tc_main(skb);
}

#if 0
/*
 * This uses tc direct-action mode to set the tc classid with skb->tc_priority
 *  To use on i.e. egress use:
 *      tc qdisc add dev wlp2s0 clsact
 *      tc filter add dev wlp2s0 egress bpf obj tc_test_da.o sec cls direct-action
 *
 * Add htq qdiscs / classes accordingly and adjust the used eBPF map -> see scripts/tc_rules_da.sh
 */
SEC("tc")
int tc_main(struct __sk_buff *skb)
{
    // data_end is a void* to the end of the packet. Needs weird casting due to kernel weirdness.
    void *data_end = (void *)(unsigned long long)skb->data_end;
    // data is a void* to the beginning of the packet. Also needs weird casting.
    void *data = (void *)(unsigned long long)skb->data;

    // nh keeps track of the beginning of the next header to parse
    struct hdr_cursor nh;

    struct ethhdr *eth;
    struct iphdr *iphdr;

    int eth_type;
    int ip_type;

    bpf_printk("hello from this program\n");

    // start parsing at beginning of data
    nh.pos = data;

    // parse ethernet
    eth_type = parse_ethhdr(&nh, data_end, &eth);

    if (eth_type == bpf_htons(ETH_P_IP)) { // if the next protocol is IPv4
        // parse IPv4
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type == IPPROTO_ICMP || ip_type == IPPROTO_TCP || ip_type == IPPROTO_UDP) {
            __u32 ip_address = iphdr->daddr; // destination IP, to be used as map lookup key
            __u32 *handle;
            struct handle_bps_delay *val_struct;
            // Map lookup
            val_struct = bpf_map_lookup_elem(&IP_HANDLE_BPS_DELAY, &ip_address);
            //handle = bpf_map_lookup_elem(&IP_TO_HANDLE_MAP, &ip_address);

            // Safety check, go on if no handle could be retrieved
            if (!val_struct) {
                return TC_ACT_OK;
            }
            handle = &val_struct->tc_handle;

            if (!handle) {
                return TC_ACT_OK;
            }

            // set handle as classid
            skb->priority = *handle;
            return TC_ACT_OK;
        }
    }
    // otherwise, use default (flowid given in TC invocation)
    return TC_ACT_OK;
}
#endif

// some eBPF kernel features are gated behind the GPL license
char _license[] SEC("license") = "GPL";
