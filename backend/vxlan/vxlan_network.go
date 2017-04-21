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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"

	"syscall"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

type network struct {
	backend.SimpleNetwork
	extIface  *backend.ExternalInterface
	dev       *vxlanDevice
	subnetMgr subnet.Manager
}

func newNetwork(subnetMgr subnet.Manager, extIface *backend.ExternalInterface, dev *vxlanDevice, _ ip.IP4Net, lease *subnet.Lease) (*network, error) {
	nw := &network{
		SimpleNetwork: backend.SimpleNetwork{
			SubnetLease: lease,
			ExtIface:    extIface,
		},
		subnetMgr: subnetMgr,
		dev:       dev,
	}

	return nw, nil
}

func (nw *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.V(0).Info("Watching for new subnet leases")
	events := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, nw.subnetMgr, nw.SubnetLease, events)
		log.V(1).Info("WatchLeases exited")
		wg.Done()
	}()

	defer wg.Wait()

	select {
	case initialEventsBatch := <-events:
		for {
			err := nw.handleInitialSubnetEvents(initialEventsBatch)
			if err == nil {
				break
			}
			log.Error(err, " About to retry")
			time.Sleep(time.Second)
		}

	case <-ctx.Done():
		return
	}

	for {
		select {
		case evtBatch := <-events:
			nw.handleSubnetEvents(evtBatch)

		case <-ctx.Done():
			return
		}
	}
}

func (nw *network) MTU() int {
	return nw.dev.MTU()
}

type vxlanLeaseAttrs struct {
	VtepMAC hardwareAddr
}

//TODO I need to fix this up
func (nw *network) handleSubnetEvents(batch []subnet.Event) {
	for _, event := range batch {
		switch event.Type {
		case subnet.EventAdded:
			log.V(1).Info("Subnet added: ", event.Lease.Subnet)

			if event.Lease.Attrs.BackendType != "vxlan" {
				log.Warningf("Ignoring non-vxlan subnet: type=%v", event.Lease.Attrs.BackendType)
				continue
			}

			var attrs vxlanLeaseAttrs
			if err := json.Unmarshal(event.Lease.Attrs.BackendData, &attrs); err != nil {
				log.Error("Error decoding subnet lease JSON: ", err)
				continue
			}
			//TODO - actually set the route
			//nw.dev.AddL3(neighbor{IP: ip.FromIP(miss.IP), MAC: route.vtepMAC}); err != nil {
			route := netlink.Route{
				LinkIndex: nw.dev.link.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       event.Lease.Subnet.ToIPNet(),
				Gw:        event.Lease.Subnet.IP.ToIP(),
			}

			log.V(1).Info("GW used: ", event.Lease.Subnet.IP.ToIP())
			if err := netlink.RouteAdd(&route); err != nil && err != syscall.EEXIST {
				panic(fmt.Errorf("failed to add route (%s -> %s): %v", route.Dst, route.Gw, err))
			}

			//nw.dev.AddFdb(neighbor{IP: event.Lease.Attrs.PublicIP, MAC: net.HardwareAddr(attrs.VtepMAC)})
			//TODO - actually set the route

		case subnet.EventRemoved:
			log.V(1).Info("Subnet removed: ", event.Lease.Subnet)

			if event.Lease.Attrs.BackendType != "vxlan" {
				log.Warningf("Ignoring non-vxlan subnet: type=%v", event.Lease.Attrs.BackendType)
				continue
			}

			var attrs vxlanLeaseAttrs
			if err := json.Unmarshal(event.Lease.Attrs.BackendData, &attrs); err != nil {
				log.Error("Error decoding subnet lease JSON: ", err)
				continue
			}

			if len(attrs.VtepMAC) > 0 {
				nw.dev.DelFdb(neighbor{IP: event.Lease.Attrs.PublicIP, MAC: net.HardwareAddr(attrs.VtepMAC)})
			}

		default:
			log.Error("Internal error: unknown event type: ", int(event.Type))
		}
	}
}

//TODO I need to fix this up
func (nw *network) handleInitialSubnetEvents(batch []subnet.Event) error {
	// The goal of this function is the ensure that the FDB (the mappings of VTEPs to public IPs) matches what's in
	// the datastore.
	// It does this by fetching the FDB, deleting ones that shouldn't be there then adding ones that should be.

	log.V(1).Infof("Handling initial subnet events")
	fdbTable, err := nw.dev.GetFdbTable()
	if err != nil {
		return fmt.Errorf("error fetching FDB table: %v", err)
	}

	// Log the existing VTEP -> Public IP mappings
	for _, fdbEntry := range fdbTable {
		log.V(1).Infof("fdb already populated with: %s %s ", fdbEntry.IP, fdbEntry.HardwareAddr)
	}

	arpTable, err := nw.dev.GetArpTable()
	if err != nil {
		return fmt.Errorf("error fetching ARP table: %v", err)
	}

	for _, arpEntry := range arpTable {
		log.V(1).Infof("arp table already populated with: %s %s ", arpEntry.IP, arpEntry.HardwareAddr)
	}

	routeTable, err := nw.dev.GetRouteTable()
	if err != nil {
		return fmt.Errorf("error fetching route table: %v", err)
	}
	for _, routeEntry := range routeTable {
		log.V(1).Infof("route table already populated with: %s nh %s ", routeEntry.Dst, routeEntry.Gw)
	}

	log.V(1).Infof("Finished fetching initial state")
	panic(0)
	// "marked" events are skipped at the end.
	eventMarker := make([]bool, len(batch))
	leaseAttrsList := make([]vxlanLeaseAttrs, len(batch))

	// "marked" fdbEntries are ones that do NOT get deleted at the end
	fdbEntryMarker := make([]bool, len(fdbTable))

	// Run through the events "marking" ones that should be skipped
	for eventMarkerIndex, evt := range batch {
		if evt.Lease.Attrs.BackendType != "vxlan" {
			log.Warningf("Ignoring non-vxlan subnet(%s): type=%v", evt.Lease.Subnet, evt.Lease.Attrs.BackendType)
			eventMarker[eventMarkerIndex] = true
			continue
		}

		// Parse the vxlan specific backend data
		if err := json.Unmarshal(evt.Lease.Attrs.BackendData, &leaseAttrsList[eventMarkerIndex]); err != nil {
			log.Error("Error decoding subnet lease JSON: ", err)
			eventMarker[eventMarkerIndex] = true
			continue
		}

		// Check the existing VTEP->Public IP mappings.
		// If there's already an entry with the right VTEP and Public IP then the event can be skipped and the FDB entry can be retained
		for j, fdbEntry := range fdbTable {
			if evt.Lease.Attrs.PublicIP.ToIP().Equal(fdbEntry.IP) && bytes.Equal([]byte(leaseAttrsList[eventMarkerIndex].VtepMAC), []byte(fdbEntry.HardwareAddr)) {
				eventMarker[eventMarkerIndex] = true
				fdbEntryMarker[j] = true
				break
			}
		}

		err := nw.dev.AddFdb(neighbor{IP: evt.Lease.Subnet.IP, MAC: net.HardwareAddr(leaseAttrsList[eventMarkerIndex].VtepMAC)})
		if err != nil {
			log.Error("Add L3 failed: ", err)
		}

		// Set the route - the kernel would ARP for the Gw IP address if it hadn't already been set above.
		log.V(2).Infof("Adding subnet: %s PublicIP: %s VtepMAC: %s", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP, net.HardwareAddr(leaseAttrsList[eventMarkerIndex].VtepMAC))

		route := netlink.Route{
			LinkIndex: nw.dev.link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       evt.Lease.Subnet.ToIPNet(),
			Gw:        evt.Lease.Subnet.IP.ToIP(),
		}
		route.SetFlag(syscall.RTNH_F_ONLINK)

		log.V(1).Info("GW used: ", evt.Lease.Subnet.IP.ToIP())
		if err := netlink.RouteAdd(&route); err != nil && err != syscall.EEXIST {
			panic(fmt.Errorf("failed to add route (%s -> %s): %v", route.Dst, route.Gw, err))
		}
		log.V(1).Info("Done")
	}

	// Loop over the existing FDB entries, deleting any that shouldn't be there
	for j, marker := range fdbEntryMarker {
		if !marker && fdbTable[j].IP != nil {
			err := nw.dev.DelFdb(neighbor{IP: ip.FromIP(fdbTable[j].IP), MAC: fdbTable[j].HardwareAddr})
			if err != nil {
				log.Error("Delete L2 failed: ", err)
			}
		}
	}

	// Loop over the events (skipping marked ones), adding them to the FDB table.
	for i, marker := range eventMarker {
		if !marker {
			err := nw.dev.AddFdb(neighbor{IP: batch[i].Lease.Attrs.PublicIP, MAC: net.HardwareAddr(leaseAttrsList[i].VtepMAC)})
			if err != nil {
				log.Error("Add L2 failed: ", err)
			}
		}
	}
	return nil
}
