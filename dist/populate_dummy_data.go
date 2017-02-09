package main

import (
	"context"
	"math/rand"
	"time"

	"fmt"

	etcdclient "github.com/coreos/etcd/client"
)

var kapi etcdclient.KeysAPI

func init() {
	// Create a random seed
	rand.Seed(time.Now().UTC().UnixNano())

	cfg := etcdclient.Config{Endpoints: []string{"http://127.0.0.1:2379"}}
	c, _ := etcdclient.New(cfg)
	kapi = etcdclient.NewKeysAPI(c)
}
func main() {
	// First set a large network
	setEtcd("/coreos.com/network/config", `{"Network": "10.0.0.0/8", "Backend": {"Type": "vxlan"}}`)

	var b = byte(0)
	var c = byte(1)

	num_remaining := 500

	// Now set up a large number of leases
	for num_remaining != 0 {
		ip := fmt.Sprintf("10.%d.%d.0", b, c)
		publicIP := fmt.Sprintf("192.168.%d.%d", b, c)
		mac := fmt.Sprintf("00:53:00:00:%02x:%02x", b, c)

		// Increment the IP, rolling over if needed
		c++
		if c == 255 {
			c = 0
			b++
		}

		fmt.Printf("Writing network:%s publicip:%s mac:%s\n", ip, publicIP, mac)
		setEtcd(fmt.Sprintf("/coreos.com/network/subnets/%s-24", ip),
			fmt.Sprintf(`{"PublicIP":"%s","BackendType":"vxlan","BackendData":{"VtepMAC":"%s"}}`, publicIP, mac))
		num_remaining--
	}
}

func setEtcd(key, value string) {
	if _, err := kapi.Set(context.Background(), key, value, nil); err != nil {
		panic(err)
	}
}
