package main

import (
	"errors"
	"net"
	"testing"
)

type MockCalls struct {
	bindPorts map[int]bool
	DefaultCalls
}

func (r *MockCalls) ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error) {
	if _, found := r.bindPorts[laddr.Port]; found {
		return nil, errors.New("port already in use")
	}
	return &UDPConnMock{
		network: network,
		laddr:   laddr,
	}, nil
}

func TestFindIPAddresses(t *testing.T) {
	router := &Router{
		WANInterfaces: []string{"lo"},
		Calls:         &MockCalls{},
	}
	ipAddresses, err := router.FindLocalIPAddresses()
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

func TestConnCreation(t *testing.T) {
	configuration := DefaultConfiguration(1)
	myIP := net.ParseIP("10.0.0.1")
	router := &Router{
		WANIPAddresses: [][]net.IP{[]net.IP{myIP}},
		WANInterfaces:  []string{"lo"},
		Configuration:  configuration,
		Calls: &MockCalls{
			bindPorts: map[int]bool{1234: true},
		},
	}

	raddr := &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 1234,
	}
	connI, err := router.udpNewConn(net.ParseIP("10.0.0.2"), raddr)
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	conn := connI.(*UDPConnMock)
	if conn.laddr.IP.String() != myIP.String() {
		t.Fatalf("expected laddr IP to be %s, got %s", conn.laddr.IP.String(), myIP.String())
	}
	if conn.laddr.Port != 1236 {
		t.Fatalf("expected laddr port to be %d, got %d", conn.laddr.Port, 1236)
	}
}
