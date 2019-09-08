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
		WANIPAddresses:                [][]net.IP{[]net.IP{myIP}},
		WANInterfaces:                 []string{"lo"},
		Configuration:                 configuration,
		connectionsByMapping:          map[string]UDPConn{},
		connectionsByInternalEndpoint: map[string][]UDPConn{},
		connectionsByExternalEndpoint: map[string][]UDPConn{},
		connectionsByRemoteEndpoint:   map[string][]UDPConn{},

		Calls: &MockCalls{
			bindPorts: map[int]bool{12345: true},
		},
	}

	laddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.2"),
		Port: 12345,
	}
	raddr := &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 1234,
	}
	connI, err := router.udpNewConn(laddr, raddr)
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	conn := connI.(*UDPConnMock)
	if conn.laddr.IP.String() != myIP.String() {
		t.Errorf("expected laddr IP to be %s, got %s", conn.laddr.IP.String(), myIP.String())
	}
	if conn.laddr.Port != 12347 {
		t.Errorf("expected laddr port to be %d, got %d", conn.laddr.Port, 12347)
	}

	if _, found := router.connectionsByMapping["10.0.0.2:12345"]; !found {
		t.Errorf("expected to find connection in mapping")
	}

	if conns, found := router.connectionsByInternalEndpoint["10.0.0.2:12345"]; !found || len(conns) != 1 {
		t.Errorf("expected to find connection in internal endpoint")
	}

	if conns, found := router.connectionsByExternalEndpoint["10.0.0.1:12347"]; !found || len(conns) != 1 {
		t.Errorf("expected to find connection in internal endpoint")
	}

	if conns, found := router.connectionsByRemoteEndpoint["1.1.1.1:1234"]; !found || len(conns) != 1 {
		t.Errorf("expected to find connection in remote endpoint")
	}
}

func TestForwardUDPPacket(t *testing.T) {
	configuration := DefaultConfiguration(1)
	myIP := net.ParseIP("10.0.0.1")
	router := &Router{
		WANIPAddresses:                [][]net.IP{[]net.IP{myIP}},
		WANInterfaces:                 []string{"lo"},
		Configuration:                 configuration,
		connectionsByMapping:          map[string]UDPConn{},
		connectionsByInternalEndpoint: map[string][]UDPConn{},
		connectionsByExternalEndpoint: map[string][]UDPConn{},
		connectionsByRemoteEndpoint:   map[string][]UDPConn{},

		Calls: &MockCalls{
			bindPorts: map[int]bool{},
		},
	}

	laddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.2"),
		Port: 12345,
	}
	raddr := &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 1234,
	}
	err := router.forwardLANUDPPacket(laddr, raddr, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	conn := router.connectionsByMapping["10.0.0.2:12345"].(*UDPConnMock)
	written := conn.written["1.1.1.1:1234"]
	if len(written) != 1 {
		t.Fatalf("expected one packet to be written, got %d", len(written))
	}

	if len(written[0]) != 3 || written[0][0] != 1 || written[0][1] != 2 || written[0][2] != 3 {
		t.Errorf("expected written data to be %v, got %v", []byte{1, 2, 3}, written[0])
	}

	err = router.forwardLANUDPPacket(laddr, raddr, []byte{4, 5})
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	// Send a new packet to the same remote
	conn = router.connectionsByMapping["10.0.0.2:12345"].(*UDPConnMock)
	written = conn.written["1.1.1.1:1234"]
	if len(written) != 2 {
		t.Fatalf("expected two packets to be written, got %d", len(written))
	}

	if len(written[1]) != 2 || written[1][0] != 4 || written[1][1] != 5 {
		t.Errorf("expected written data to be %v, got %v", []byte{4, 5}, written[1])
	}

	// Send a new packet to another remote
	raddr = &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.2"),
		Port: 1239,
	}
	err = router.forwardLANUDPPacket(laddr, raddr, []byte{6, 7})
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	conn = router.connectionsByMapping["10.0.0.2:12345"].(*UDPConnMock)
	written = conn.written["1.1.1.2:1239"]
	if len(written) != 1 {
		t.Fatalf("expected two packets to be written, got %d", len(written))
	}

	if len(written[0]) != 2 || written[0][0] != 6 || written[0][1] != 7 {
		t.Errorf("expected written data to be %v, got %v", []byte{6, 7}, written[0])
	}
}
