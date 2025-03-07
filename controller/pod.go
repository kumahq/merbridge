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

package controller

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	kumanet_ebpf "github.com/kumahq/kuma-net/ebpf"
	kumanet_config "github.com/kumahq/kuma-net/transparent-proxy/config"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/internal/ebpfs"
	"github.com/merbridge/merbridge/internal/pods"
	"github.com/merbridge/merbridge/pkg/linux"
)

func RunLocalPodController(client kubernetes.Interface, stop chan struct{}) error {
	var err error

	if err = ebpfs.InitLoadPinnedMap(); err != nil {
		return fmt.Errorf("failed to load ebpf maps: %v", err)
	}

	w := pods.NewWatcher(createLocalPodController(client))

	if err = w.Start(); err != nil {
		return fmt.Errorf("start watcher failed: %v", err)
	}

	log.Info("Pod Watcher Ready")

	programs := []*kumanet_ebpf.Program{
		ebpfs.MBConnect,
		ebpfs.MBSockops,
		ebpfs.MBGetSockopts,
		ebpfs.MBSendmsg,
		ebpfs.MBRecvmsg,
		ebpfs.MBRedir,
	}

	cfg := kumanet_config.Config{
		RuntimeStdout: os.Stderr,
		RuntimeStderr: os.Stderr,
		Ebpf: kumanet_config.Ebpf{
			Enabled:            true,
			BPFFSPath:          "/sys/fs/bpf",
			ProgramsSourcePath: "/app/bpf",
		},
		Verbose: config.Debug,
	}

	if err := kumanet_ebpf.LoadAndAttachEbpfPrograms(programs, cfg); err != nil {
		return fmt.Errorf("failed to load ebpf programs: %v", err)
	}

	if config.EnableCNI {
		<-stop
	} else {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)
		<-ch
	}
	w.Shutdown()

	warning, err := kumanet_ebpf.UnloadEbpfPrograms(programs, cfg)
	if err != nil {
		return fmt.Errorf("failed to cleanup after ebpf programs: %s", err)
	}

	if warning != "" {
		_, _ = fmt.Fprintln(os.Stderr, warning)
	}

	log.Info("Pod Watcher Down")
	return nil
}

func createLocalPodController(client kubernetes.Interface) pods.Watcher {
	localName, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	return pods.Watcher{
		Client:          client,
		CurrentNodeName: localName,
		OnAddFunc:       addFunc,
		OnUpdateFunc:    updateFunc,
		OnDeleteFunc:    deleteFunc,
	}
}

const MaxItemLen = 10 // todo changeme

type cidr struct {
	net  uint32 // network order
	mask uint8
	_    [3]uint8 // pad
}

type podConfig struct {
	statusPort       uint16
	_                uint16 // pad
	excludeOutRanges [MaxItemLen]cidr
	includeOutRanges [MaxItemLen]cidr
	includeInPorts   [MaxItemLen]uint16
	includeOutPorts  [MaxItemLen]uint16
	excludeInPorts   [MaxItemLen]uint16
	excludeOutPorts  [MaxItemLen]uint16
}

func addFunc(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok || len(pod.Status.PodIP) == 0 {
		return
	}
	if config.Mode == config.ModeIstio && !pods.IsIstioInjectedSidecar(pod) {
		return
	}
	if config.Mode == config.ModeLinkerd && !pods.IsLinkerdInjectedSidecar(pod) {
		return
	}
	if config.Mode == config.ModeKuma && !pods.IsKumaInjectedSidecar(pod) {
		return
	}
	log.Debugf("got pod updated %s/%s", pod.Namespace, pod.Name)

	_ip, _ := linux.IP2Linux(pod.Status.PodIP)
	log.Infof("update local_pod_ips with ip: %s", pod.Status.PodIP)
	p := podConfig{}
	if config.Mode == config.ModeKuma {
		parsePodConfigFromAnnotationsKuma(pod.Annotations, &p)
	} else {
		parsePodConfigFromAnnotations(pod.Annotations, &p)
	}
	err := ebpfs.GetPinnedMap().Update(_ip, &p, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("update local_pod_ips %s error: %v", pod.Status.PodIP, err)
	}
}

func getPortsFromString(v string) []uint16 {
	var ports []uint16
	for _, vv := range strings.Split(v, ",") {
		if p := strings.TrimSpace(vv); p != "" {
			port, err := strconv.ParseUint(vv, 10, 16)
			if err == nil {
				ports = append(ports, uint16(port))
			}
		}
	}
	return ports
}

func getIPRangesFromString(v string) []cidr {
	var ranges []cidr
	for _, vv := range strings.Split(v, ",") {
		if vv == "*" {
			ranges = append(ranges, cidr{
				net:  0,
				mask: 0,
			})
			continue
		}
		if p := strings.TrimSpace(vv); p != "" {
			_, n, err := net.ParseCIDR(vv)
			if err != nil {
				log.Errorf("parse cidr from %s error: %v", vv, err)
				continue
			}
			c := cidr{}
			ones, _ := n.Mask.Size()
			c.mask = uint8(ones)
			if len(n.IP) == 16 {
				c.net = *(*uint32)(unsafe.Pointer(&n.IP[12]))
			} else {
				c.net = *(*uint32)(unsafe.Pointer(&n.IP[0]))
			}
			ranges = append(ranges, c)
		}
	}
	return ranges
}

func parsePodConfigFromAnnotations(annotations map[string]string, pod *podConfig) {
	statusPort := 15021
	if v, ok := annotations["status.sidecar.istio.io/port"]; ok {
		vv, err := strconv.ParseUint(v, 10, 16)
		if err == nil {
			statusPort = int(vv)
		}
	}
	pod.statusPort = uint16(statusPort)
	excludeInboundPorts := []uint16{15006, 15001, 15008, 15090, 15021, 15020, 15000} // todo changeme
	if v, ok := annotations["traffic.sidecar.istio.io/excludeInboundPorts"]; ok {
		excludeInboundPorts = append(excludeInboundPorts, getPortsFromString(v)...)
	}
	if len(excludeInboundPorts) > 0 {
		for i, p := range excludeInboundPorts {
			if i >= MaxItemLen {
				break
			}
			pod.excludeInPorts[i] = p
		}
	}
	if v, ok := annotations["traffic.sidecar.istio.io/excludeOutboundPorts"]; ok {
		excludeOutboundPorts := getPortsFromString(v)
		if len(excludeOutboundPorts) > 0 {
			for i, p := range excludeOutboundPorts {
				if i >= MaxItemLen {
					break
				}
				pod.excludeOutPorts[i] = p
			}
		}
	}

	if v, ok := annotations["traffic.sidecar.istio.io/includeInboundPorts"]; ok {
		includeInboundPorts := getPortsFromString(v)
		if len(includeInboundPorts) > 0 {
			for i, p := range includeInboundPorts {
				if i >= MaxItemLen {
					break
				}
				pod.includeInPorts[i] = p
			}
		}
	}
	if v, ok := annotations["traffic.sidecar.istio.io/includeInboundPorts"]; ok {
		includeOutboundPorts := getPortsFromString(v)
		if len(includeOutboundPorts) > 0 {
			for i, p := range includeOutboundPorts {
				if i >= MaxItemLen {
					break
				}
				pod.includeOutPorts[i] = p
			}
		}
	}

	if v, ok := annotations["traffic.sidecar.istio.io/excludeOutboundIPRanges"]; ok {
		excludeOutboundIPRanges := getIPRangesFromString(v)
		if len(excludeOutboundIPRanges) > 0 {
			for i, p := range excludeOutboundIPRanges {
				if i >= MaxItemLen {
					break
				}
				pod.excludeOutRanges[i] = p
			}
		}
	}
	if v, ok := annotations["traffic.sidecar.istio.io/includeOutboundIPRanges"]; ok {
		includeOutboundIPRanges := getIPRangesFromString(v)
		if len(includeOutboundIPRanges) > 0 {
			for i, p := range includeOutboundIPRanges {
				if i >= MaxItemLen {
					break
				}
				pod.includeOutRanges[i] = p
			}
		}
	}
}

func parsePodConfigFromAnnotationsKuma(annotations map[string]string, pod *podConfig) {
	excludeInboundPorts := []uint16{9901, 15001, 15006, 15010} // todo changeme
	// FIXME: Whether to need to consistent with the naming Isito an Annotation: hump method
	if v, ok := annotations["traffic.kuma.io/exclude-inbound-ports"]; ok {
		excludeInboundPorts = append(excludeInboundPorts, getPortsFromString(v)...)
	}
	if len(excludeInboundPorts) > 0 {
		for i, p := range excludeInboundPorts {
			if i >= MaxItemLen {
				break
			}
			pod.excludeInPorts[i] = p
		}
	}
	if v, ok := annotations["traffic.kuma.io/exclude-outbound-ports"]; ok {
		excludeOutboundPorts := getPortsFromString(v)
		if len(excludeOutboundPorts) > 0 {
			for i, p := range excludeOutboundPorts {
				if i >= MaxItemLen {
					break
				}
				pod.excludeOutPorts[i] = p
			}
		}
	}
}

func updateFunc(old, cur interface{}) {
	oldPod, ok := old.(*v1.Pod)
	if !ok {
		return
	}
	curPod, ok := cur.(*v1.Pod)
	if !ok {
		return
	}
	if oldPod.Status.PodIP != curPod.Status.PodIP {
		// only care about ip changes
		addFunc(cur)
	}
}

func deleteFunc(obj interface{}) {
	if pod, ok := obj.(*v1.Pod); ok {
		log.Debugf("got pod delete %s/%s", pod.Namespace, pod.Name)
		_ip, _ := linux.IP2Linux(pod.Status.PodIP)
		_ = ebpfs.GetPinnedMap().Delete(_ip)
	}
}
