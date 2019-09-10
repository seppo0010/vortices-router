package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

type MockCalls struct {
	bindPorts  map[int]bool
	interfaces map[string]bytes.Buffer
	now        map[NowUsage][]time.Time
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

func (m *MockCalls) Now(usage NowUsage) time.Time {
	if m.now == nil {
		return m.DefaultCalls.Now(usage)
	}
	if nowUsageList, found := m.now[usage]; !found || len(nowUsageList) == 0 {
		panic(fmt.Sprintf("missing usage for %d", usage))
	}
	t := m.now[usage][0]
	m.now[usage] = m.now[usage][1:]
	return t
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
		t.Errorf("expected source ip to be %v, got %v instead", "1.1.1.1", ipv4Layer.SrcIP.String())
	}
	if ipv4Layer.DstIP.String() != "10.0.0.2" {
		t.Errorf("expected source ip to be %v, got %v instead", "10.0.0.2", ipv4Layer.DstIP.String())
	}
	if udpLayer.SrcPort != 1723 {
		t.Errorf("expected source port to be %v, got %v instead", 1724, udpLayer.SrcPort)
	}
	if udpLayer.DstPort != 12345 {
		t.Errorf("expected source port to be %v, got %v instead", 12345, udpLayer.DstPort)
	}
	if len(udpLayer.Payload) != 3 || udpLayer.Payload[0] != 1 || udpLayer.Payload[1] != 2 || udpLayer.Payload[2] != 3 {
		t.Errorf("expected payload to be #%v, got %#v instead", []byte{1, 2, 3}, udpLayer.Payload)
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

func testFilter(t *testing.T, configuration *Configuration, forward bool, raddr net.Addr) *Router {
	return testFilterWithCalls(t, configuration, forward, raddr, &MockCalls{
		bindPorts: map[int]bool{9876: true},
	})
}

func testFilterWithCalls(t *testing.T, configuration *Configuration, forward bool, raddr net.Addr, calls *MockCalls) *Router {
	log.SetOutput(ioutil.Discard)

	myIP := net.ParseIP("10.0.0.1")
	router := &Router{
		WANIPAddresses:                [][]net.IP{[]net.IP{myIP}},
		WANInterfaces:                 []string{"lo"},
		Configuration:                 configuration,
		connectionsByMapping:          map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string][]*UDPConnContext{},

		Calls: calls,
	}

	laddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.2"),
		Port: 12344,
	}
	srcMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	dstMAC, _ := net.ParseMAC("10:00:5e:00:53:02")
	cont := &UDPConnContext{
		lanInterface:  "eth23",
		interfaceMAC:  srcMAC,
		internalMAC:   dstMAC,
		internalAddr:  laddr,
		externalAddrs: []net.Addr{raddr},
		UDPConn: &UDPConnMock{
			laddr: &net.UDPAddr{
				IP:   net.ParseIP("10.0.0.1"),
				Port: 9876,
			},
			toRead: []*UDPConnPacket{
				&UDPConnPacket{
					data: []byte{1, 2, 3},
					addr: &net.UDPAddr{
						IP:   net.ParseIP("1.1.1.1"),
						Port: 12345,
					},
				},
			},
		},
	}
	router.addUDPConn(laddr, raddr, cont)

	router.processUDPConnOnce(cont)
	buffer := router.Calls.(*MockCalls).interfaces["eth23"]
	if !forward && len(buffer.Bytes()) != 0 {
		t.Fatalf("expected no forwarding, got %d bytes", len(buffer.Bytes()))
	} else if forward && len(buffer.Bytes()) == 0 {
		t.Fatalf("expected forwarding, got 0 bytes")
	}
	return router
}

func TestAcceptFilterEndpointIndependent(t *testing.T) {
	configuration := DefaultConfiguration(1)
	testFilter(t, configuration, true, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12345})
	testFilter(t, configuration, true, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12344})
	testFilter(t, configuration, true, &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 12344})
	testFilter(t, configuration, true, &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12345})
}

func TestAcceptFilterAddressDependent(t *testing.T) {
	configuration := DefaultConfiguration(1)
	configuration.Filtering = FilteringAddressDependent{}
	testFilter(t, configuration, true, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12345})
	testFilter(t, configuration, true, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12344})
	testFilter(t, configuration, false, &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 12344})
	testFilter(t, configuration, true, &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12345})
}

func TestAcceptFilterAddressAndPortDependent(t *testing.T) {
	configuration := DefaultConfiguration(1)
	configuration.Filtering = FilteringAddressAndPortDependent{}
	testFilter(t, configuration, true, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12345})
	testFilter(t, configuration, false, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12344})
	testFilter(t, configuration, false, &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 12344})
	testFilter(t, configuration, false, &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12345})
}

func TestReadUpdatesLastRead(t *testing.T) {
	configuration := DefaultConfiguration(1)

	lastRead := time.Date(2019, time.January, 3, 4, 5, 6, 7, time.UTC)
	calls := &MockCalls{
		bindPorts: map[int]bool{9876: true},
		now: map[NowUsage][]time.Time{
			NowUsageInitRead:     []time.Time{},
			NowUsageInitWrite:    []time.Time{},
			NowUsageRead:         []time.Time{lastRead},
			NowUsageWrite:        []time.Time{},
			NowUsageReadDeadline: []time.Time{time.Date(2020, time.January, 3, 4, 5, 6, 7, time.UTC)},
			NowUsageWriteEvict:   []time.Time{},
			NowUsageReadEvict:    []time.Time{},
		},
	}
	router := testFilterWithCalls(t, configuration, true, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 12345}, calls)
	cont := router.connectionsByMapping["10.0.0.2:12344"]
	if cont.lastRead != lastRead {
		t.Errorf("expected last read to be %v, got %v instead", lastRead, cont.lastRead)
	}
}

func TestWriteUpdatesLastWrite(t *testing.T) {
	configuration := DefaultConfiguration(1)
	lastWrite := time.Date(2019, time.January, 3, 4, 5, 6, 7, time.UTC)
	myIP := net.ParseIP("10.0.0.1")
	router := &Router{
		WANIPAddresses:                [][]net.IP{[]net.IP{myIP}},
		WANInterfaces:                 []string{"lo"},
		Configuration:                 configuration,
		connectionsByMapping:          map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string][]*UDPConnContext{},

		Calls: &MockCalls{
			bindPorts: map[int]bool{},
			now: map[NowUsage][]time.Time{
				NowUsageInitRead:     []time.Time{time.Date(2019, time.February, 9, 4, 5, 6, 7, time.UTC)},
				NowUsageInitWrite:    []time.Time{time.Date(2019, time.February, 3, 4, 5, 6, 7, time.UTC)},
				NowUsageRead:         []time.Time{},
				NowUsageWrite:        []time.Time{lastWrite},
				NowUsageReadDeadline: []time.Time{},
				NowUsageWriteEvict:   []time.Time{},
				NowUsageReadEvict:    []time.Time{},
			},
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

	cont := router.connectionsByMapping["10.0.0.2:12345"]
	if cont.lastWrite != lastWrite {
		t.Errorf("expected last write to be %v, got %v instead", lastWrite, cont.lastWrite)
	}
}

func TestSetsReadDeadline(t *testing.T) {
	configuration := DefaultConfiguration(1)
	configuration.MappingRefresh = 8 * time.Second

	readDeadline := time.Date(2019, time.February, 3, 4, 5, 6, 7, time.UTC)
	calls := &MockCalls{
		bindPorts: map[int]bool{9876: true},
		now: map[NowUsage][]time.Time{
			NowUsageInitRead:     []time.Time{},
			NowUsageInitWrite:    []time.Time{},
			NowUsageRead:         []time.Time{},
			NowUsageWrite:        []time.Time{},
			NowUsageReadDeadline: []time.Time{readDeadline},
			NowUsageWriteEvict:   []time.Time{},
			NowUsageReadEvict:    []time.Time{},
		},
	}

	log.SetOutput(ioutil.Discard)
	myIP := net.ParseIP("10.0.0.1")
	router := &Router{
		WANIPAddresses:                [][]net.IP{[]net.IP{myIP}},
		WANInterfaces:                 []string{"lo"},
		Configuration:                 configuration,
		connectionsByMapping:          map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string][]*UDPConnContext{},

		Calls: calls,
	}

	laddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.2"),
		Port: 12344,
	}
	raddr := &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 1234,
	}
	srcMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	dstMAC, _ := net.ParseMAC("10:00:5e:00:53:02")
	cont := &UDPConnContext{
		lanInterface:  "eth23",
		interfaceMAC:  srcMAC,
		internalMAC:   dstMAC,
		internalAddr:  laddr,
		externalAddrs: []net.Addr{raddr},
		UDPConn: &UDPConnMock{
			laddr: &net.UDPAddr{
				IP:   net.ParseIP("10.0.0.1"),
				Port: 9876,
			},
			toRead: []*UDPConnPacket{},
		},
	}
	router.addUDPConn(laddr, raddr, cont)

	router.processUDPConnOnce(cont)
	setReadDeadline := router.connectionsByMapping["10.0.0.2:12344"].UDPConn.(*UDPConnMock).readDeadline
	expected := readDeadline.Add(configuration.MappingRefresh)
	if setReadDeadline != expected {
		t.Errorf("expected set read deadline to be %v, got %v", expected, setReadDeadline)
	}
}

func TestFinishesOnDeadline(t *testing.T) {
	t.Error("unimplemented")
}

func TestDoesntFinishIfInboudRefresh(t *testing.T) {
	t.Error("unimplemented")
}

func TestDoesFinishIfNoInboudRefresh(t *testing.T) {
	t.Error("unimplemented")
}
