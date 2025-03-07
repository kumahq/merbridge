/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "headers/helpers.h"
#include "headers/mesh.h"

const volatile short unsigned int out_redirect_port = 15001;
const volatile short unsigned int in_redirect_port = 15006;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct origin_info));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_orig_dst SEC(".maps");

// process_ip stores envoy's ip address.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} process_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(struct pair));
    __uint(value_size, sizeof(struct origin_info));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pair_orig_dst SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(struct pair));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_pair_map SEC(".maps");

#if ENABLE_IPV4
static inline int sockops_ipv4(struct bpf_sock_ops *skops)
{
    __u64 cookie = bpf_get_socket_cookie(skops);

    struct pair p;
    memset(&p, 0, sizeof(p));
    set_ipv4(p.sip, skops->local_ip4);
    p.sport = bpf_htons(skops->local_port);
    set_ipv4(p.dip, skops->remote_ip4);
    p.dport = skops->remote_port >> 16;

    struct origin_info *dst = bpf_map_lookup_elem(&cookie_orig_dst, &cookie);
    if (dst) {
        struct origin_info dd = *dst;
        if (!(dd.flags & 1)) {
            __u32 pid = dd.pid;
            __u32 remote_ip = skops->remote_ip4;
            __u32 local_ip = skops->local_ip4;
            // process ip not detected
            if (local_ip == envoy_ip || local_ip == remote_ip) {
                // envoy to local
                debugf("sock4 : detected process %d's ip is %pI4", pid,
                       &remote_ip);
                bpf_map_update_elem(&process_ip, &pid, &remote_ip, BPF_ANY);
#ifdef USE_RECONNECT
                if (skops->remote_port >> 16 == bpf_htons(in_redirect_port)) {
                    printk("sock4 : incorrect connection: cookie=%d", cookie);
                    return 1;
                }
#endif
            } else {
                // envoy to envoy
                bpf_map_update_elem(&process_ip, &pid, &local_ip, BPF_ANY);
                debugf("sock4 : detected process %d's ip is %pI4", pid,
                       &local_ip);
            }
        }
        // get_sockopts can read pid and cookie,
        // we should write a new map named pair_orig_dst
        bpf_map_update_elem(&pair_orig_dst, &p, &dd, BPF_ANY);
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    } else if (skops->local_port == out_redirect_port ||
               skops->local_port == in_redirect_port ||
               skops->remote_ip4 == envoy_ip) {
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    }
    return 0;
}
#endif

#if ENABLE_IPV6
static inline int sockops_ipv6(struct bpf_sock_ops *skops)
{
    __u64 cookie = bpf_get_socket_cookie(skops);
    struct pair p;
    memset(&p, 0, sizeof(p));
    p.sport = bpf_htons(skops->local_port);
    p.dport = skops->remote_port >> 16;
    set_ipv6(p.sip, skops->local_ip6);
    set_ipv6(p.dip, skops->remote_ip6);

    struct origin_info *dst = bpf_map_lookup_elem(&cookie_orig_dst, &cookie);
    if (dst) {
        struct origin_info dd = *dst;
        // get_sockopts can read pid and cookie,
        // we should write a new map named pair_orig_dst
        bpf_map_update_elem(&pair_orig_dst, &p, &dd, BPF_ANY);
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    } else if (skops->local_port == out_redirect_port ||
               skops->local_port == in_redirect_port ||
               ipv6_equal(skops->remote_ip6, envoy_ip6)) {
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    }
    return 0;
}
#endif

SEC("sockops") int mb_sockops(struct bpf_sock_ops *skops)
{
    switch (skops->op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        switch (skops->family) {
#if ENABLE_IPV4
        case 2:
            // AF_INET, we don't include socket.h, because it may
            // cause an import error.
            return sockops_ipv4(skops);
#endif
#if ENABLE_IPV6
        case 10:
            // AF_INET6
            return sockops_ipv6(skops);
#endif
        }
        return 0;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
