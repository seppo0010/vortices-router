package main

import "testing"

func TestFindIPAddresses(t *testing.T) {
	router := &Router{
		WANInterfaces: []string{"lo"},
	}
	ipAddresses, err := router.findLocalIPAddresses()
	if err != nil {
		t.Fatalf("%s", err)
	}
	if ipAddresses == nil || len(ipAddresses) == 0 || ipAddresses[0] == nil || len(ipAddresses[0]) == 0 {
		t.Fatalf("expected to have at least one ip address in local interface")
	}

	for _, ip := range ipAddresses[0] {
		if !ip.IsLoopback() {
			t.Fatalf("found not loopback ip address in local interface")
		}
	}
}
