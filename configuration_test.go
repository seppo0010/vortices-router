package main

import (
	"net"
	"testing"
)

func TestIPAddressPoolingPaired(t *testing.T) {
	numIPAddresses := 3
	pool := NewIPAddressPoolingPaired(numIPAddresses)
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.0.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
		net.ParseIP("127.0.0.2"),
	}
	lastIP := net.ParseIP("127.0.0.3")

	// new IPs should round robin
	for i, ip := range ips {
		index := pool.GetIndexForIP(ip)
		if index != i%numIPAddresses {
			t.Errorf("expected index %d for ip %s, got %d", i, ip.String(), index)
		}
	}

	// existing IPs should maintain their index
	for i, ip := range ips {
		index := pool.GetIndexForIP(ip)
		if index != i%numIPAddresses {
			t.Errorf("expected index %d for ip %s, got %d", i, ip.String(), index)
		}
	}

	// trying a new one just in case reads messed it up
	index := pool.GetIndexForIP(lastIP)
	if index != len(ips)%numIPAddresses {
		t.Errorf("expected index %d for ip %s, got %d", len(ips), lastIP.String(), index)
	}
}
