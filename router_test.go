package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MockCalls struct {
	bindPorts  map[int]bool
	interfaces map[string]bytes.Buffer
	DefaultCalls
}

func (m *MockCalls) ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error) {
	if _, found := m.bindPorts[laddr.Port]; found {
		return nil, errors.New("port already in use")
	}
	return &UDPConnMock{
		network: network,
		laddr:   laddr,
	}, nil
}

func (m *MockCalls) OpenInterface(device string) (InterfaceHandle, error) {
	return &MockInterfaceHandle{
		device: device,
		write: func(d []byte) {
			if m.interfaces == nil {
				m.interfaces = map[string]bytes.Buffer{}
			}
			buffer := m.interfaces[device]
			buffer.Write(d)
			m.interfaces[device] = buffer
		},
	}, nil
}

type MockInterfaceHandle struct {
	device string
	closed bool
	write  func([]byte)
}

func (m *MockInterfaceHandle) Close() {
	if m.closed {
		panic("closing interface handle twice")
	}
}

func (m *MockInterfaceHandle) WritePacketData(data []byte) error {
	if m.closed {
		return errors.New("writing packet data in closed interface handle|MockInterfaceHandle")
	}
	m.write(data)
	return nil
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
		connectionsByMapping:          map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string][]*UDPConnContext{},
		connectionsByExternalEndpoint: map[string][]*UDPConnContext{},
		connectionsByRemoteEndpoint:   map[string][]*UDPConnContext{},

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
	connI, err := router.udpNewConn(laddr, raddr, net.HardwareAddr{}, net.HardwareAddr{}, "")
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	conn := connI.UDPConn.(*UDPConnMock)
	if conn.laddr.IP.String() != myIP.String() {
		t.Errorf("expected laddr IP to be %s, got %s", conn.laddr.IP.String(), myIP.String())
	}
	if conn.laddr.Port != 12347 {
		t.Errorf("expected laddr port to be %d, got %d", conn.laddr.Port, 12347)
	}

	if _, found := router.connectionsByMapping["10.0.0.2:12345"]; !found {
		t.Errorf("expected to find connection in mapping")
	}

	if _, found := router.connectionsByInternalEndpoint["10.0.0.2:12345"]; !found {
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
		connectionsByMapping:          map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string][]*UDPConnContext{},
		connectionsByExternalEndpoint: map[string][]*UDPConnContext{},
		connectionsByRemoteEndpoint:   map[string][]*UDPConnContext{},

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
	err := router.forwardLANUDPPacket(laddr, raddr, net.HardwareAddr{}, net.HardwareAddr{}, "", []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	conn := router.connectionsByMapping["10.0.0.2:12345"].UDPConn.(*UDPConnMock)
	written := conn.written["1.1.1.1:1234"]
	if len(written) != 1 {
		t.Fatalf("expected one packet to be written, got %d", len(written))
	}

	if len(written[0]) != 3 || written[0][0] != 1 || written[0][1] != 2 || written[0][2] != 3 {
		t.Errorf("expected written data to be %v, got %v", []byte{1, 2, 3}, written[0])
	}

	err = router.forwardLANUDPPacket(laddr, raddr, net.HardwareAddr{}, net.HardwareAddr{}, "", []byte{4, 5})
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	// Send a new packet to the same remote
	conn = router.connectionsByMapping["10.0.0.2:12345"].UDPConn.(*UDPConnMock)
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
	err = router.forwardLANUDPPacket(laddr, raddr, net.HardwareAddr{}, net.HardwareAddr{}, "", []byte{6, 7})
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	conn = router.connectionsByMapping["10.0.0.2:12345"].UDPConn.(*UDPConnMock)
	written = conn.written["1.1.1.2:1239"]
	if len(written) != 1 {
		t.Fatalf("expected two packets to be written, got %d", len(written))
	}

	if len(written[0]) != 2 || written[0][0] != 6 || written[0][1] != 7 {
		t.Errorf("expected written data to be %v, got %v", []byte{6, 7}, written[0])
	}
}

func TestForwardWANUDPPacket(t *testing.T) {
	configuration := DefaultConfiguration(1)
	myIP := net.ParseIP("10.0.0.1")
	router := &Router{
		WANIPAddresses:                [][]net.IP{[]net.IP{myIP}},
		WANInterfaces:                 []string{"lo"},
		Configuration:                 configuration,
		connectionsByMapping:          map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string][]*UDPConnContext{},
		connectionsByExternalEndpoint: map[string][]*UDPConnContext{},
		connectionsByRemoteEndpoint:   map[string][]*UDPConnContext{},

		Calls: &MockCalls{
			bindPorts: map[int]bool{},
		},
	}
	srcMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	dstMAC, _ := net.ParseMAC("10:00:5e:00:53:02")
	err := router.forwardWANUDPPacket(&UDPConnContext{
		lanInterface: "eth23",
		interfaceMAC: srcMAC,
		internalMAC:  dstMAC,
		internalAddr: &net.UDPAddr{
			IP:   net.ParseIP("10.0.0.2"),
			Port: 12345,
		},
	}, &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 1723,
	}, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("error forwading packet: %s", err.Error())
	}
	buffer := router.Calls.(*MockCalls).interfaces["eth23"]
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	udpLayer := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	if ipv4Layer.SrcIP.String() != "1.1.1.1" {
		fmt.Errorf("expected source ip to be %v, got %v instead", "1.1.1.1", ipv4Layer.SrcIP.String())
	}
	if ipv4Layer.DstIP.String() != "10.0.0.2" {
		fmt.Errorf("expected source ip to be %v, got %v instead", "10.0.0.2", ipv4Layer.DstIP.String())
	}
	if udpLayer.SrcPort != 1723 {
		fmt.Errorf("expected source port to be %v, got %v instead", 1724, udpLayer.SrcPort)
	}
	if udpLayer.DstPort != 12345 {
		fmt.Errorf("expected source port to be %v, got %v instead", 12345, udpLayer.DstPort)
	}
	if len(udpLayer.Payload) != 3 || udpLayer.Payload[0] != 1 || udpLayer.Payload[1] != 2 || udpLayer.Payload[2] != 3 {
		fmt.Errorf("expected payload to be #%v, got %#v instead", []byte{1, 2, 3}, udpLayer.Payload)
	}
}

func TestConnCreationContiguity(t *testing.T) {
	configuration := DefaultConfiguration(1)
	myIP := net.ParseIP("10.0.0.1")
	router := &Router{
		WANIPAddresses:       [][]net.IP{[]net.IP{myIP}},
		WANInterfaces:        []string{"lo"},
		Configuration:        configuration,
		connectionsByMapping: map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string][]*UDPConnContext{
			"10.0.0.2:12344": []*UDPConnContext{
				&UDPConnContext{
					UDPConn: &UDPConnMock{
						laddr: &net.UDPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 9876,
						},
					},
				},
			},
		},
		connectionsByExternalEndpoint: map[string][]*UDPConnContext{},
		connectionsByRemoteEndpoint:   map[string][]*UDPConnContext{},

		Calls: &MockCalls{
			bindPorts: map[int]bool{9876: true},
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
	connI, err := router.udpNewConn(laddr, raddr, net.HardwareAddr{}, net.HardwareAddr{}, "")
	if err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	conn := connI.UDPConn.(*UDPConnMock)
	if conn.laddr.Port != 9877 {
		t.Errorf("expected connection port to be 9877, got %v", conn.laddr.Port)
	}
}

func TestAcceptFilterEndpointIndependent(t *testing.T) {
	t.Fatal("unimplemented")
}

func TestAcceptFilterAddressDependent(t *testing.T) {
	t.Fatal("unimplemented")
}
func TestAcceptFilterAddressAndPortDependent(t *testing.T) {
	t.Fatal("unimplemented")
}
func TestAcceptFilterAddressAndPortDependentDifferentProtocol(t *testing.T) {
	t.Fatal("unimplemented")
}
