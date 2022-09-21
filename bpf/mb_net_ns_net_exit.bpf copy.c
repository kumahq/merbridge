#include "headers/helpers.h"
#include "headers/mesh.h"
#include "headers/maps.h"

__section("kprobe/net_ns_net_exit") int mb_net_ns_net_exit(struct net *net)
{
#if MESH != KUMA
    // only works on kuma
    return 0;
#endif
    __u64 netns_inum = BPF_CORE_READ(net, ns.inum);
	_u32 *ip = bpf_map_lookup_elem(&mark_pod_ips, &netns_inum);
    if (!ip) {
        debugf("net_ns_net_exit : net namespace isn't in eBPF: %u",
               netns_inum);
    } else {
        bpf_map_delete_elem(&local_pod_ips, &ip);
        debugf("net_ns_net_exit : removed ip for netns: netns_inum: %u, ip: %pI4", netns_inum,
               &curr_pod_ip);
    }
    return 0;
}
