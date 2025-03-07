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

package cniserver

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"
	kumanet_ebpf "github.com/kumahq/kuma-net/ebpf"
	kumanet_config "github.com/kumahq/kuma-net/transparent-proxy/config"
	log "github.com/sirupsen/logrus"
	"istio.io/istio/cni/pkg/plugin"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/internal/ebpfs"
	"github.com/merbridge/merbridge/pkg/linux"
)

type qdisc struct {
	netns  string
	device string
}

func (s *server) CmdAdd(args *skel.CmdArgs) (err error) {
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("merbridge-cni panicked during cmdAdd: %v\n%v", e, string(debug.Stack()))
			if err != nil {
				// If we're recovering and there was also an error, then we need to
				// present both.
				msg = fmt.Sprintf("%s: %v", msg, err)
			}
			err = fmt.Errorf(msg)
		}
		if err != nil {
			log.Errorf("merbridge-cni cmdAdd error: %v", err)
		}
	}()
	k8sArgs := plugin.K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		return err
	}
	netns, err := ns.GetNS("/host" + args.Netns)
	if err != nil {
		log.Errorf("get ns %s error", args.Netns)
		return err
	}

	err = netns.Do(func(_ ns.NetNS) error {
		if err := s.updateNetNSPodIPsMap(netns.Path()); err != nil {
			return err
		}
		// attach tc to the device
		if len(args.IfName) != 0 {
			return s.attachTC(netns.Path(), args.IfName)
		}
		// interface not specified, should not happen?
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if (iface.Flags&net.FlagLoopback) == 0 && (iface.Flags&net.FlagUp) != 0 {
				return s.attachTC(netns.Path(), iface.Name)
			}
		}
		return fmt.Errorf("device not found for %s", args.Netns)
	})
	if err != nil {
		log.Errorf("CmdAdd failed for %s: %v", args.Netns, err)
		return err
	}
	return err
}

func (s *server) CmdDelete(args *skel.CmdArgs) (err error) {
	k8sArgs := plugin.K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		return err
	}
	netns := "/host" + args.Netns
	inode, err := linux.GetFileInode(netns)
	if err != nil {
		return err
	}
	s.Lock()

	delete(s.qdiscs, inode)

	s.Unlock()
	m, err := ebpf.LoadPinnedMap(path.Join(s.bpfMountPath, "netns_pod_ips"), &ebpf.LoadPinOptions{})
	if err != nil {
		return err
	}
	return m.Delete(inode)
}

func getAddr() (*net.Addr, error) {
	var addrs []net.Addr

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagLoopback) != 0 || (iface.Flags&net.FlagUp) == 0 {
			continue
		}

		ifAddrs, err := iface.Addrs()
		if err != nil || len(ifAddrs) == 0 {
			continue
		}

		addrs = append(addrs, ifAddrs...)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no ip address")
	}

	if len(addrs) != 1 {
		log.Warnf("get ip address, res: %v, merbridge only support single ip address", addrs)
	}

	return &addrs[0], nil
}

func (s *server) updateNetNSPodIPsMap(netns string) error {
	inode, err := linux.GetFileInode(netns)
	if err != nil {
		return err
	}

	addr, err := getAddr()
	if err != nil {
		return err
	}

	m, err := ebpf.LoadPinnedMap(path.Join(s.bpfMountPath, "netns_pod_ips"), &ebpf.LoadPinOptions{})
	if err != nil {
		return err
	}

	var ip unsafe.Pointer
	switch v := (*addr).(type) {
	case *net.IPNet: // nolint: typecheck
		ip, err = linux.IP2Linux(v.IP.String())
	case *net.IPAddr: // nolint: typecheck
		ip, err = linux.IP2Linux(v.String())
	}
	if err != nil {
		return err
	}

	if err := m.Update(inode, ip, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating netns_pod_ips map failed (ip: %v, nens: %v): %v", ip, inode, err)
	}

	return nil
}

func (s *server) checkAndRepairPodPrograms() error {
	hostProc, err := os.ReadDir(config.HostProc)
	if err != nil {
		return err
	}

	namespaces := map[uintptr]ns.NetNS{}

	for _, f := range hostProc {
		if _, err = strconv.Atoi(f.Name()); err == nil {
			pid := f.Name()
			if skipPid(s.serviceMeshMode, pid) {
				// ignore non-injected pods
				log.Debugf("skip listening for pid(%s)", pid)
				continue
			}

			np := fmt.Sprintf("%s/%s/ns/net", config.HostProc, pid)
			netns, err := ns.GetNS(np)
			if err != nil {
				log.Errorf("Failed to get ns for %s, error: %v", np, err)
				continue
			}

			namespaces[netns.Fd()] = netns
		}
	}

	for _, netns := range namespaces {
		if err = netns.Do(func(_ ns.NetNS) error {
			log.Infof("build listener for netns: %s", netns.Path())

			if err := s.updateNetNSPodIPsMap(netns.Path()); err != nil {
				return err
			}

			// attach tc to the device
			ifaces, _ := net.Interfaces()
			for _, iface := range ifaces {
				if (iface.Flags&net.FlagLoopback) == 0 && (iface.Flags&net.FlagUp) != 0 {
					return s.attachTC(netns.Path(), iface.Name)
				}
			}

			return fmt.Errorf("device not found for netns: %s", netns.Path())
		}); err != nil {
			return err
		}
	}

	return nil
}

func skipPid(serviceMeshMode string, pid string) bool {
	b, _ := os.ReadFile(fmt.Sprintf("%s/%s/comm", config.HostProc, pid))
	comm := strings.TrimSpace(string(b))

	switch serviceMeshMode {
	case config.ModeKuma:
		if comm != "kuma-dp" {
			return true
		}
	default:
		if comm != "pilot-agent" {
			return true
		}
	}

	findStr := func(path string, str []byte) bool {
		f, _ := os.Open(path)
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Split(bufio.ScanLines)
		for sc.Scan() {
			if bytes.Contains(sc.Bytes(), str) {
				return true
			}
		}
		return false
	}

	if config.EnableIPV4 {
		conn4 := fmt.Sprintf("%s/%s/net/tcp", config.HostProc, pid)
		return !findStr(conn4, []byte(fmt.Sprintf(": %0.8d:%0.4X %0.8d:%0.4X 0A", 0, 15001, 0, 0)))
	}
	conn6 := fmt.Sprintf("%s/%s/net/tcp6", config.HostProc, pid)
	return !findStr(conn6, []byte(fmt.Sprintf(": %0.32d:%0.4X %0.32d:%0.4X 0A", 0, 15001, 0, 0)))
}

func (s *server) attachTC(netns, dev string) error {
	inode, err := linux.GetFileInode(netns)
	if err != nil {
		return err
	}

	if err := kumanet_ebpf.LoadAndAttachEbpfPrograms([]*kumanet_ebpf.Program{
		ebpfs.MBTc,
	}, kumanet_config.Config{
		RuntimeStdout: os.Stderr,
		RuntimeStderr: os.Stderr,
		Ebpf: kumanet_config.Ebpf{
			Enabled:            true,
			BPFFSPath:          "/sys/fs/bpf",
			ProgramsSourcePath: "/app/bpf",
			TCAttachIface:      dev,
		},
		Verbose: config.Debug,
	}); err != nil {
		return fmt.Errorf("failed to load ebpf programs: %v", err)
	}

	s.Lock()
	s.qdiscs[inode] = qdisc{
		netns:  netns,
		device: dev,
	}
	s.Unlock()
	return nil
}

func (s *server) cleanUpTC() {
	s.Lock()
	defer s.Unlock()
	for _, q := range s.qdiscs {
		netns, err := ns.GetNS(q.netns)
		if err != nil {
			log.Errorf("Failed to get ns for %s, error: %v", q.netns, err)
			continue
		}
		if err = netns.Do(func(_ ns.NetNS) error {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("tc filter delete dev %s egress prio 66", q.device))
			err := cmd.Run()
			if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
				return fmt.Errorf("failed to delete egress filter from %s, unexpected exit code: %d, err: %v", q.device, code, err)
			}
			cmd = exec.Command("sh", "-c", fmt.Sprintf("tc filter delete dev %s ingress prio 66", q.device))
			err = cmd.Run()
			if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
				return fmt.Errorf("failed to delete ingress filter from %s, unexpected exit code: %d, err: %v", q.device, code, err)
			}
			return nil
		}); err != nil {
			log.Errorf("Failed to clean up tc for %s, error: %v", q.netns, err)
		}
	}
}
