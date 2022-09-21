#include "headers/helpers.h"
#include "headers/mesh.h"
#include "headers/maps.h"

SEC("kprobe/net_ns_net_exit")
int BPF_KPROBE(net_ns_net_exit, struct net *net)
{
   
    __u64 netns_inum = BPF_CORE_READ(net, ns.inum);
     bpf_printk("KPROBE ENTRY  inum: %u \n", netns_inum);
	__u32 *ip = bpf_map_lookup_elem(&netns_pod_ips, &netns_inum);

    if (!ip) {
        debugf("net_ns_net_exit : net namespace isn't in eBPF: %u",
               netns_inum);
    } else {
        bpf_map_delete_elem(&local_pod_ips, ip);
        debugf("net_ns_net_exit : removed ip for netns from local_pod_ips: netns_inum: %u, ip: %pI4", netns_inum,
               &ip);
        bpf_map_delete_elem(&netns_pod_ips, &netns_inum);
        debugf("net_ns_net_exit : removed netns_inum for netns_pod_ips: netns_inum: %u", netns_inum); 
    }
    return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;