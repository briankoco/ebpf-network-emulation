// helpers for ebpf programs

// hdr_cursor is used to keep track of the current position in data parsing
struct hdr_cursor {
    void * pos;
};

// vxlanhdr represents the fields of a VXLAN packet header
struct vxlanhdr {
    __u64 flags : 8;
    __u64 rsvd1 : 8;
    __u64 gid   : 16;
    __u64 vni   : 24;
    __u64 rsvd2 : 8;
};

// Must be 0000 1000
#define vxlanhdr_is_valid(hdr) (hdr->flags == 0x8)

// ntohl fixes endianness of the upper 32 bits (vni+rsvd2); this brings the last 8 bits (rsvd2)
// to the front, which we shift off to get the vni
#define vxlanhdr_vni(hdr) bpf_ntohl(hdr->vni) >> 8

// parse_ethhdr parses the ethernet header of a packet, and performs necessary bounds checks.
// It returns the next protocol
static __always_inline
int parse_ethhdr(struct hdr_cursor * nh,
                 void              * data_end,
                 struct ethhdr    ** ethhdr)
{
    struct ethhdr * eth = nh->pos;
    int hdrsize = sizeof(*eth);

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto; /* network-byte-order */
}

// parse_iphdr parses the IP header of a packet, and performs necessary bounds checks
// (more complicated due to variable length of IPv4). It returns the next protocol
static __always_inline
int parse_iphdr(struct hdr_cursor * nh,
                void              * data_end,
                struct iphdr     ** iphdr)
{
    struct iphdr * iph = nh->pos;
    int hdrsize;

    if (nh->pos + sizeof(*iph) > data_end)
        return -1;

    hdrsize = iph->ihl * 4;
    /* Sanity check packet field is valid */
    if(hdrsize < sizeof(*iph))
        return -1;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

// parse_udphdr parsed the UDP header of a packet, and performs the necessary bounds checks.
// It returns the length of the UDP payload
static __always_inline
int parse_udphdr(struct hdr_cursor * nh,
                 void              * data_end,
                 struct udphdr    ** udphdr)
{
    struct udphdr * h = nh->pos;
    int len, hdrsize = sizeof(*h);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *udphdr = h;

    len = bpf_ntohs(h->len) - hdrsize;
    if (len < 0)
        return -1;

    return len;
}

// parse_vxlanhdr parsed the VXLAN header of a packet, and performs the necessary bounds checks.
// It returns 1 if header is a valid VXLAN header, -1 if not
static __always_inline
int parse_vxlanhdr(struct hdr_cursor * nh,
                   void              * data_end,
                   struct vxlanhdr  ** vxlanhdr)
{
    struct vxlanhdr * vh = nh->pos;

    int hdrsize = sizeof(*vh);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *vxlanhdr = vh;

    // whether VXLAN hdr is valid
    if (vxlanhdr_is_valid(vh))
        return 1;
    else
        return -1;
}
