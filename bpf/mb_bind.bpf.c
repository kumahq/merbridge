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
const volatile unsigned int sidecar_user_id = 1337;

// this prog hook linkerd bind OUTPUT_LISTENER
// which will makes the listen address change from 127.0.0.1:4140 to
// 0.0.0.0:4140
#if ENABLE_IPV4
SEC("cgroup/bind4") int mb_bind(struct bpf_sock_addr *ctx)
{
#if MESH != LINKERD
    // only works on linkerd
    return 1;
#endif

    if (ctx->user_ip4 == 0x0100007f &&
        ctx->user_port == bpf_htons(out_redirect_port)) {
        __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
        if (uid == sidecar_user_id) {
            // linkerd listen localhost, we have to change the bind address to
            // 0.0.0.0:4140
            printk(
                "bind4 : change bind address from 127.0.0.1:%d to 0.0.0.0:%d",
                out_redirect_port, out_redirect_port);
            ctx->user_ip4 = 0;
        }
    }
    return 1;
}
#endif

char LICENSE[] SEC("license") = "GPL";
