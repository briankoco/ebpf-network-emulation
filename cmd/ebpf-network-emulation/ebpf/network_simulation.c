#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/stddef.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "helpers.h"
#include "maps.h"

/* Adapted from: https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/progs/test_tc_edt.c */

/* the maximum delay we are willing to add (drop packets beyond that) */
#define TIME_HORIZON_NS (2000 * 1000 * 1000)
#define NS_PER_SEC 1000000000
#define ECN_HORIZON_NS 500000000
#define NS_PER_MS 1000000


/* flow_key => last_tstamp timestamp used */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 65535);
} flow_map SEC(".maps");


static inline int inject_delay(struct __sk_buff *skb, uint32_t *delay_ms) {
    uint64_t delay_ns;
    uint64_t now = bpf_ktime_get_ns();
    delay_ns = (*delay_ms) * NS_PER_MS;
    uint64_t ts = skb->tstamp;
    uint64_t new_ts = ((uint64_t)skb->tstamp) + delay_ns;

    // debug msg, read with 
    // sudo cat /sys/kernel/debug/tracing/trace_pipe
    //const char fmt_ts[] = "skb Tstamp: %d\n";
    //bpf_trace_printk(fmt_ts, sizeof(fmt_ts), ts);
    //const char fmt_str[] = "Now Tstamp: %d\n";
    //bpf_trace_printk(fmt_str, sizeof(fmt_str), now);
    //const char fmt_str2[] = "Now + delay Tstamp: %d\n";
    //bpf_trace_printk(fmt_str2, sizeof(fmt_str2), now + delay_ns);
    //const char fmt_str3[] = "New Tstamp: %d\n";
    //bpf_trace_printk(fmt_str3, sizeof(fmt_str3), new_ts);

    // sometimes skb-tstamp is reset to 0
    // https://patchwork.kernel.org/project/netdevbpf/patch/20220301053637.930759-1-kafai@fb.com/
    // check if skb->tstamp == 0
    if (ts == 0) {
        skb->tstamp = now + delay_ns;
        return TC_ACT_OK;
    }
    // otherwise add additional delay to packets 
    skb->tstamp = new_ts;

    return TC_ACT_OK;
}

/*
 * For some reason section names need to start with "tc"
 * TODO: Remove duplicate header parsing code
 */
SEC("tc2")
int set_delay(struct __sk_buff *skb)
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

    // start parsing at beginning of data
    nh.pos = data;

    // parse ethernet
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type == IPPROTO_ICMP || ip_type == IPPROTO_TCP || ip_type == IPPROTO_UDP) {
            __u32 ip_address = iphdr->daddr; // destination IP, to be used as map lookup key
            __u32 *delay_ms;
            struct handle_bps_delay *val_struct;
            // Map lookup
            val_struct = bpf_map_lookup_elem(&IP_HANDLE_BPS_DELAY, &ip_address);

            // Safety check, go on if no handle could be retrieved
            if (!val_struct) {
                return TC_ACT_OK;
            }

            delay_ms = &val_struct->delay_ms;
            // Safety check, go on if no handle could be retrieved
            if (!delay_ms) {
                return TC_ACT_OK;
            }

            return inject_delay(skb, delay_ms);
        }
    }
    return TC_ACT_OK;
}


struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(max_entries, 2);
	__uint(pinning, LIBBPF_PIN_BY_NAME); // pin map by name (accessible under /sys/fs/bpf/<name>)
	__array(values, int ());
} progs SEC(".maps");

static inline int throttle_flow(struct __sk_buff *skb, __u32 ip_address, uint32_t *throttle_rate_bps)
{
    // use ip as key in map
    int key = ip_address;

    // when was the last packet sent?
    uint64_t *last_tstamp = bpf_map_lookup_elem(&flow_map, &key);
    // calculate delay between packets based on bandwidth and packet size (bps = byte/second)
    uint64_t delay_ns = ((uint64_t)skb->len) * NS_PER_SEC / *throttle_rate_bps;

    uint64_t now = bpf_ktime_get_ns();
    uint64_t tstamp, next_tstamp = 0;

    // calculate the next timestamp
    if (last_tstamp)
        next_tstamp = *last_tstamp + delay_ns;

    // if the current timestamp of the packet is in the past, use the current time
    tstamp = skb->tstamp;
    if (tstamp < now)
        tstamp = now;

    // if the delayed timestamp is already in the past, send the packet
    if (next_tstamp <= tstamp) {
        //const char fmt_past[] = "We're living in the past -> next_tstamp: %d, tstamp -> %d\n";
        //bpf_trace_printk(fmt_past, sizeof(fmt_past), next_tstamp, tstamp);
        if (bpf_map_update_elem(&flow_map, &key, &tstamp, BPF_ANY))
            return TC_ACT_SHOT;
        //set additional delay for packet
        bpf_tail_call(skb, &progs, 0);
        return TC_ACT_OK;
    }

    // do not queue for more than 2s, just drop packet instead
    if (next_tstamp - now >= TIME_HORIZON_NS)
        return TC_ACT_SHOT;

    /* set ecn bit, if needed */
    if (next_tstamp - now >= ECN_HORIZON_NS)
        bpf_skb_ecn_set_ce(skb);

    // update last timestamp in map
    if (bpf_map_update_elem(&flow_map, &key, &next_tstamp, BPF_EXIST))
        return TC_ACT_SHOT;


    //const char fmt_throt[] = "Throttled:  -> skb_tstamp: %d, next_tstamp: %d\n";
    //bpf_trace_printk(fmt_throt, sizeof(fmt_throt), skb->tstamp, next_tstamp);
    // set delayed timestamp for packet
    skb->tstamp = next_tstamp;

    //set additional delay for packet
    bpf_tail_call(skb, &progs, 0);
    
    return TC_ACT_OK;
}

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

    // start parsing at beginning of data
    nh.pos = data;

    // parse ethernet
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type == IPPROTO_ICMP || ip_type == IPPROTO_TCP || ip_type == IPPROTO_UDP) {
            __u32 ip_address = iphdr->daddr; // destination IP, to be used as map lookup key
            __u32 *throttle_rate_bps;
            struct handle_bps_delay *val_struct;
            // Map lookup
            val_struct = bpf_map_lookup_elem(&IP_HANDLE_BPS_DELAY, &ip_address);

            // Safety check, go on if no handle could be retrieved
            if (!val_struct) {
                return TC_ACT_OK;
            }
            throttle_rate_bps = &val_struct->throttle_rate_bps;
            // Safety check, go on if no handle could be retrieved
            if (!throttle_rate_bps)  {
                return TC_ACT_OK;
            }
            return throttle_flow(skb, ip_address, throttle_rate_bps);
        }
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
