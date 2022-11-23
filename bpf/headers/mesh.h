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

#ifndef MESH_H
#define MESH_H

#define ISTIO 1
#define LINKERD 2
#define KUMA 3

#ifndef MESH
#define MESH 1
#endif

#if MESH == ISTIO
// 127.0.0.6 (network order)
static const __u32 envoy_ip = 127 + (6 << 24);
// ::6 (network order)
static const __u32 envoy_ip6[4] = {0, 0, 0, 6 << 24};

#elif MESH == LINKERD
// 127.0.0.6 (network order)
static const __u32 envoy_ip = 127 + (6 << 24);
// ::6 (network order)
static const __u32 envoy_ip6[4] = {0, 0, 0, 6 << 24};

#elif MESH == KUMA
// 127.0.0.6 (network order)
static const __u32 envoy_ip = 127 + (6 << 24);
// ::6 (network order)
static const __u32 envoy_ip6[4] = {0, 0, 0, 6 << 24};

#else
#error "Mesh mode not supported yet"
#endif

#endif
