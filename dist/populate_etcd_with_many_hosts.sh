#!/usr/bin/env bash
# First set a large "network"
etcdctl set /coreos.com/network/config '{ "Network": "10.0.0.0/8", "Backend": {"Type": "vxlan"}}'

# Now create a large number of dummy leases
etcdctl set /coreos.com/network/subnets/10.5.51.0-24 '{"PublicIP":"10.10.10.12","BackendType":"vxlan","BackendData":{"VtepMAC":"82:4b:b6:2f:54:45"}}'
