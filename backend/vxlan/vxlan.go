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

import "fmt"

// Some design notes and history:
// VXLAN encapsulates L2 packets (though flannel is L3 only so don't expect to be able to send L2 packets across hosts)
// The first versions of vxlan for flannel registed the flannel daemon as a handler for both "L2" and "L3" misses
// - When a container send a packet to a new IP address on the flannel network this generates an L2 miss (i.e. an ARP lookup)
// - The flannel daemon knows which flannel host the packet is destined for so it can supply the VTEP MAC to use
// - The packet can then be encapsulated but the host needs to know where to send it. This creates another callout to the
// flannel daemon to get the public IP that should be used for that VTEP (this gets called an L3 miss). The L2/L3 miss
// hooks are registered when the vxlan device is created. At the same time a device route is created to the whole
// flannel network so that non-local traffic is sent over the vxlan device.
//
// In this screme, on each host there is
//  - 1 route (for the configured network out the vxlan device)
//  - One arp entry for each ??? container that we're talking to
//  - One FDB entry for each ??? host?
//
// The second version of flannel vxlan removed the need for the L3MISS callout. When a new remote host is found (either
// during startup or when it's created), flannel simply adds the required entries so that no further lookup/callout is required.
//
//
// The latest version of version removes the need for the L2MISS too, which means that the flannel deamon is not
// listening for any netlink messages anymore which improves reliablility (no worries about things timing out if
// flannel crashes or restarts) and simplifies upgrades.
//
// How it works:
// For each remote host
// 1) create an route dev route but with the right subnet and next hop
// 2) Create an ARP entry for every IP owned by that host?
	NOOOOO this is wrong.
What do I create an ARP entry for?
// 3) Create an FDB entry?
//

// 1 route per host, 1 arp entry and one FDB entry per host

import (
	"encoding/json"
	"fmt"
	"net"

	"golang.org/x/net/context"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

func init() {
	backend.Register("vxlan", New)
}

const (
	defaultVNI = 1
)

type VXLANBackend struct {
	subnetMgr subnet.Manager
	extIface  *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	backend := &VXLANBackend{
		subnetMgr: sm,
		extIface:  extIface,
	}

	return backend, nil
}

func newSubnetAttrs(publicIP net.IP, mac net.HardwareAddr) (*subnet.LeaseAttrs, error) {
	data, err := json.Marshal(&vxlanLeaseAttrs{hardwareAddr(mac)})
	if err != nil {
		return nil, err
	}

	return &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(publicIP),
		BackendType: "vxlan",
		BackendData: json.RawMessage(data),
	}, nil
}

func (be *VXLANBackend) Run(ctx context.Context) {
	<-ctx.Done()
}

func (be *VXLANBackend) RegisterNetwork(ctx context.Context, config *subnet.Config) (backend.Network, error) {
	// Parse our configuration
	cfg := struct {
		VNI  int
		Port int
		GBP  bool
	}{
		VNI: defaultVNI,
	}

	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding VXLAN backend config: %v", err)
		}
	}

	devAttrs := vxlanDeviceAttrs{
		vni:       uint32(cfg.VNI),
		name:      fmt.Sprintf("flannel.%v", cfg.VNI),
		vtepIndex: be.extIface.Iface.Index,
		vtepAddr:  be.extIface.IfaceAddr,
		vtepPort:  cfg.Port,
		gbp:       cfg.GBP,
	}

	dev, err := newVXLANDevice(&devAttrs)
	if err != nil {
		return nil, err
	}

	subnetAttrs, err := newSubnetAttrs(be.extIface.ExtAddr, dev.MACAddr())
	if err != nil {
		return nil, err
	}

	lease, err := be.subnetMgr.AcquireLease(ctx, subnetAttrs)
	switch err {
	case nil:

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// vxlan's subnet is just that for this host
	vxlanNet := ip.IP4Net{
		IP:        lease.Subnet.IP,
		PrefixLen: 32,
	}
	if err = dev.Configure(vxlanNet); err != nil {
		return nil, err
	}

	return newNetwork(be.subnetMgr, be.extIface, dev, vxlanNet, lease)
}

// So we can make it JSON (un)marshalable
type hardwareAddr net.HardwareAddr

func (hw hardwareAddr) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", net.HardwareAddr(hw))), nil
}

func (hw *hardwareAddr) UnmarshalJSON(bytes []byte) error {
	if len(bytes) < 2 || bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return fmt.Errorf("error parsing hardware addr")
	}

	bytes = bytes[1 : len(bytes)-1]

	mac, err := net.ParseMAC(string(bytes))
	if err != nil {
		return err
	}

	*hw = hardwareAddr(mac)
	return nil
}
