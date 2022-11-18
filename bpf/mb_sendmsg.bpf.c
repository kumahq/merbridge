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
const volatile unsigned int sidecar_user_id = 1337;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct origin_info));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_orig_dst SEC(".maps");

#if ENABLE_IPV4
SEC("cgroup/sendmsg4") int mb_sendmsg4(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio and kuma
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != 53) {
        return 1;
    }
    if (!(is_port_listen_current_ns(ctx, ip_zero, out_redirect_port) &&
          is_port_listen_udp_current_ns(ctx, localhost, dns_capture_port))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != sidecar_user_id) {
        __u64 cookie = bpf_get_socket_cookie(ctx);
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, ctx->user_ip4);
        origin.port = ctx->user_port;
        // save original dst
        if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("send4 : update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(dns_capture_port);
        ctx->user_ip4 = localhost;
    }
    return 1;
}
#endif

#if ENABLE_IPV6
SEC("cgroup/sendmsg6") int mb_sendmsg6(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != 53) {
        return 1;
    }
    if (!(is_port_listen_current_ns6(ctx, ip_zero6, out_redirect_port) &&
          is_port_listen_udp_current_ns6(ctx, localhost6, dns_capture_port))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != sidecar_user_id) {
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        origin.port = ctx->user_port;
        set_ipv6(origin.ip, ctx->user_ip6);
        // save original dst
        __u64 cookie = bpf_get_socket_cookie(ctx);
        if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("send : update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(dns_capture_port);
        set_ipv6(ctx->user_ip6, localhost6);
    }
    return 1;
}
#endif

char LICENSE[] SEC("license") = "GPL";
