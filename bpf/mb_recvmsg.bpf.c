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
const volatile short unsigned int dns_capture_port = 15053;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct origin_info));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_orig_dst SEC(".maps");

#if ENABLE_IPV4
SEC("cgroup/recvmsg4") int mb_recvmsg4(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio and kuma
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != dns_capture_port) {
        return 1;
    }
    if (!(is_port_listen_current_ns(ctx, ip_zero, out_redirect_port) &&
          is_port_listen_udp_current_ns(ctx, localhost, dns_capture_port))) {
        // printk("recv4 : not from pod");
        return 1;
    }
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct origin_info *origin =
        (struct origin_info *)bpf_map_lookup_elem(&cookie_orig_dst, &cookie);
    if (origin) {
        ctx->user_port = origin->port;
        ctx->user_ip4 = get_ipv4(origin->ip);
        debugf("recv4 : successfully deal DNS redirect query");
    } else {
        printk("recv4 : failed to get origin");
    }
    return 1;
}
#endif

#if ENABLE_IPV6
SEC("cgroup/recvmsg6") int mb_recvmsg6(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != dns_capture_port) {
        return 1;
    }
    if (!(is_port_listen_current_ns6(ctx, ip_zero6, out_redirect_port) &&
          is_port_listen_udp_current_ns6(ctx, localhost6, dns_capture_port))) {
        // printk("recv6 : not from pod");
        return 1;
    }

    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct origin_info *origin =
        (struct origin_info *)bpf_map_lookup_elem(&cookie_orig_dst, &cookie);
    if (origin) {
        ctx->user_port = origin->port;
        set_ipv6(ctx->user_ip6, origin->ip);
        debugf("recv6 : successfully deal DNS redirect query");
    } else {
        printk("recv6 : failed to get origin");
    }
    return 1;
}
#endif

char LICENSE[] SEC("license") = "GPL";
