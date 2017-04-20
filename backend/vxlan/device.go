// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vxlan

import (
	"fmt"
	"net"
	"syscall"

	log "github.com/golang/glog"
	"github.com/vishvananda/netlink"

	"github.com/coreos/flannel/pkg/ip"
)

type vxlanDeviceAttrs struct {
	vni       uint32
	name      string
	vtepIndex int
	vtepAddr  net.IP
	vtepPort  int
	gbp       bool
}

type vxlanDevice struct {
	link *netlink.Vxlan
}

func newVXLANDevice(devAttrs *vxlanDeviceAttrs) (*vxlanDevice, error) {
	link := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: devAttrs.name,
		},
		VxlanId:      int(devAttrs.vni),
		VtepDevIndex: devAttrs.vtepIndex,
		SrcAddr:      devAttrs.vtepAddr,
		Port:         devAttrs.vtepPort,
		Learning:     false,
		GBP:          devAttrs.gbp,
	}

	link, err := ensureLink(link)
	if err != nil {
		return nil, err
	}
	return &vxlanDevice{
		link: link,
	}, nil
}

func ensureLink(vxlan *netlink.Vxlan) (*netlink.Vxlan, error) {
	err := netlink.LinkAdd(vxlan)
	if err == syscall.EEXIST {
		// it's ok if the device already exists as long as config is similar
		log.V(1).Infof("VXLAN device already exists")
		existing, err := netlink.LinkByName(vxlan.Name)
		if err != nil {
			return nil, err
		}

		incompat := vxlanLinksIncompat(vxlan, existing)
		if incompat == "" {
			log.V(1).Infof("Returning existing device")
			return existing.(*netlink.Vxlan), nil
		}

		// delete existing
		log.Warningf("%q already exists with incompatable configuration: %v; recreating device", vxlan.Name, incompat)
		if err = netlink.LinkDel(existing); err != nil {
			return nil, fmt.Errorf("failed to delete interface: %v", err)
		}

		// create new
		if err = netlink.LinkAdd(vxlan); err != nil {
			return nil, fmt.Errorf("failed to create vxlan interface: %v", err)
		}
	} else if err != nil {
		return nil, err
	}

	ifindex := vxlan.Index
	link, err := netlink.LinkByIndex(vxlan.Index)
	if err != nil {
		return nil, fmt.Errorf("can't locate created vxlan device with index %v", ifindex)
	}

	var ok bool
	if vxlan, ok = link.(*netlink.Vxlan); !ok {
		return nil, fmt.Errorf("created vxlan device with index %v is not vxlan", ifindex)
	}

	return vxlan, nil
}

func (dev *vxlanDevice) Configure(ipn ip.IP4Net) error {
	setAddr4(dev.link, ipn.ToIPNet())

	if err := netlink.LinkSetUp(dev.link); err != nil {
		return fmt.Errorf("failed to set interface %s to UP state: %s", dev.link.Attrs().Name, err)
	}

	// explicitly add a route since there might be a route for a subnet already
	// installed by Docker and then it won't get auto added
	route := netlink.Route{
		LinkIndex: dev.link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       ipn.Network().ToIPNet(),
	}
	if err := netlink.RouteAdd(&route); err != nil && err != syscall.EEXIST {
		return fmt.Errorf("failed to add route (%s -> %s): %v", ipn.Network().String(), dev.link.Attrs().Name, err)
	}

	return nil
}

func (dev *vxlanDevice) Destroy() {
	log.V(1).Infof("Removing existing VXLAN device dev.link.Index: %d ", dev.link.Index)
	netlink.LinkDel(dev.link)
}

func (dev *vxlanDevice) MACAddr() net.HardwareAddr {
	return dev.link.HardwareAddr
}

func (dev *vxlanDevice) MTU() int {
	return dev.link.MTU
}

type neighbor struct {
	MAC net.HardwareAddr
	IP  ip.IP4
}

func (dev *vxlanDevice) GetFdbTable() ([]netlink.Neigh, error) {
	log.V(4).Infof("calling GetFdbTable() dev.link.Index: %d ", dev.link.Index)
	return netlink.NeighList(dev.link.Index, syscall.AF_BRIDGE)
}

func (dev *vxlanDevice) GetArpTable() ([]netlink.Neigh, error) {
	log.V(4).Infof("calling GetArpTable() dev.link.Index: %d ", dev.link.Index)
	return netlink.NeighList(dev.link.Index, syscall.AF_INET)
}

func (dev *vxlanDevice) GetRouteTable() ([]netlink.Route, error) {
	log.V(4).Infof("calling GetRouteTable() dev.link.Index: %d ", dev.link.Index)
	return netlink.RouteList(dev.link, syscall.AF_INET)
}

func (dev *vxlanDevice) AddFdb(n neighbor) error {
	log.V(4).Infof("calling AddFdb: %v, %v", n.IP, n.MAC)
	return netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) DelFdb(n neighbor) error {
	log.V(4).Infof("calling DelFdb: %v, %v", n.IP, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) AddArp(n neighbor) error {
	log.V(4).Infof("calling AddArp: %v, %v", n.IP, n.MAC)
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func (dev *vxlanDevice) DelArp(n neighbor) error {
	log.V(4).Infof("calling DelArp: %v, %v", n.IP, n.MAC)
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           n.IP.ToIP(),
		HardwareAddr: n.MAC,
	})
}

func vxlanLinksIncompat(l1, l2 netlink.Link) string {
	if l1.Type() != l2.Type() {
		return fmt.Sprintf("link type: %v vs %v", l1.Type(), l2.Type())
	}

	v1 := l1.(*netlink.Vxlan)
	v2 := l2.(*netlink.Vxlan)

	if v1.VxlanId != v2.VxlanId {
		return fmt.Sprintf("vni: %v vs %v", v1.VxlanId, v2.VxlanId)
	}

	if v1.VtepDevIndex > 0 && v2.VtepDevIndex > 0 && v1.VtepDevIndex != v2.VtepDevIndex {
		return fmt.Sprintf("vtep (external) interface: %v vs %v", v1.VtepDevIndex, v2.VtepDevIndex)
	}

	if len(v1.SrcAddr) > 0 && len(v2.SrcAddr) > 0 && !v1.SrcAddr.Equal(v2.SrcAddr) {
		return fmt.Sprintf("vtep (external) IP: %v vs %v", v1.SrcAddr, v2.SrcAddr)
	}

	if len(v1.Group) > 0 && len(v2.Group) > 0 && !v1.Group.Equal(v2.Group) {
		return fmt.Sprintf("group address: %v vs %v", v1.Group, v2.Group)
	}

	if v1.L2miss != v2.L2miss {
		return fmt.Sprintf("l2miss: %v vs %v", v1.L2miss, v2.L2miss)
	}

	if v1.Port > 0 && v2.Port > 0 && v1.Port != v2.Port {
		return fmt.Sprintf("port: %v vs %v", v1.Port, v2.Port)
	}
	return ""
}

// sets IP4 addr on link
func setAddr4(link *netlink.Vxlan, ipn *net.IPNet) error {
	// Ensure that the device has a /32 address so that no broadcast routes are created.
	// This IP is just used as a source address for host to workload traffic (so
	// the return path for the traffic has a decent address to use as the destination)
	ipn.Mask = net.CIDRMask(32, 32)
	addr := netlink.Addr{IPNet: ipn, Label: ""}
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return fmt.Errorf("failed to add IP address %s to %s: %s", ipn.String(), link.Attrs().Name, err)
	}

	return nil
}
