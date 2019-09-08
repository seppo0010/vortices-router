package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var NoPorts = errors.New("no available ports")

type Calls interface {
	Interfaces() ([]net.Interface, error)
	ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error)
}
type Router struct {
	Configuration *Configuration
	LANInterfaces []string
	LANQueues     []int
	WANInterfaces []string
	WANQueues     []int

	// WANIPAddresses contain a list of IPs on each LAN Interface, these might be IPv4 or IPv6
	WANIPAddresses                [][]net.IP
	connectionsByMapping          map[string]UDPConn
	connectionsByInternalEndpoint map[string][]UDPConn
	connectionsByExternalEndpoint map[string][]UDPConn
	connectionsByRemoteEndpoint   map[string][]UDPConn
	Calls
}

func NewRouter(conf *Configuration, lanInterfaces []string, lanQueues []int, wanInterfaces []string, wanQueues []int) (*Router, error) {
	var err error
	router := &Router{
		Configuration:                 conf,
		LANInterfaces:                 lanInterfaces,
		WANInterfaces:                 wanInterfaces,
		LANQueues:                     lanQueues,
		WANQueues:                     wanQueues,
		Calls:                         defaultCalls,
		connectionsByMapping:          map[string]UDPConn{},
		connectionsByInternalEndpoint: map[string][]UDPConn{},
		connectionsByExternalEndpoint: map[string][]UDPConn{},
		connectionsByRemoteEndpoint:   map[string][]UDPConn{},
	}
	router.WANIPAddresses, err = router.FindLocalIPAddresses()
	return router, err
}

func (r *Router) Run() {
	panic("unimplemented")
}

func (r *Router) wanIPsForLANIP(lanIP net.IP) []net.IP {
	if len(r.WANIPAddresses) == 1 {
		return r.WANIPAddresses[0]
	}
	return r.WANIPAddresses[r.Configuration.IPAddressPooling.GetIndexForIP(lanIP)]
}

func (r *Router) FindLocalIPAddresses() ([][]net.IP, error) {
	ifaces, err := r.Calls.Interfaces()
	if err != nil {
		return nil, err
	}
	ipAddresses := make([][]net.IP, len(r.WANInterfaces))
	for i, _ := range ipAddresses {
		ipAddresses[i] = nil
	}

	for _, i := range ifaces {
		index := func(needle string, haystack []string) int {
			for i, v := range haystack {
				if needle == v {
					return i
				}
			}
			return -1
		}(i.Name, r.WANInterfaces)
		if index == -1 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		ips := []net.IP{}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ips = append(ips, ip)
		}
		ipAddresses[index] = ips
	}
	for i, ipAddress := range ipAddresses {
		if ipAddress == nil || len(ipAddress) == 0 {
			return nil, fmt.Errorf("unable to find ip address for network %s", r.WANInterfaces[i])
		}
	}
	return ipAddresses, nil
}

func (r *Router) addUDPConn(laddr, eaddr, raddr *net.UDPAddr, udpConn UDPConn) {
	mapping := r.Configuration.GetMapping(laddr, raddr)
	if existingConn, found := r.connectionsByMapping[mapping]; found {
		existingConn.Close()
	}
	r.connectionsByMapping[mapping] = udpConn

	internalEndpoint := laddr.String()
	if _, found := r.connectionsByInternalEndpoint[internalEndpoint]; !found {
		r.connectionsByInternalEndpoint[internalEndpoint] = []UDPConn{}
	}
	r.connectionsByInternalEndpoint[internalEndpoint] = append(r.connectionsByInternalEndpoint[internalEndpoint], udpConn)

	externalEndpoint := eaddr.String()
	if _, found := r.connectionsByExternalEndpoint[externalEndpoint]; !found {
		r.connectionsByExternalEndpoint[externalEndpoint] = []UDPConn{}
	}
	r.connectionsByExternalEndpoint[externalEndpoint] = append(r.connectionsByExternalEndpoint[externalEndpoint], udpConn)

	remoteEndpoint := raddr.String()
	if _, found := r.connectionsByRemoteEndpoint[remoteEndpoint]; !found {
		r.connectionsByRemoteEndpoint[remoteEndpoint] = []UDPConn{}
	}
	r.connectionsByRemoteEndpoint[remoteEndpoint] = append(r.connectionsByRemoteEndpoint[remoteEndpoint], udpConn)
}

func (r *Router) udpNewConn(laddr, raddr *net.UDPAddr) (UDPConn, error) {
	wanIPs := r.wanIPsForLANIP(laddr.IP)
	portCandidates, stop := r.Configuration.GetExternalPortForInternalPort(laddr.Port)
	for portCandidate := range portCandidates {
		for _, wanIP := range wanIPs {
			// TODO: handle portCandidate.Force
			eaddr := &net.UDPAddr{
				IP:   wanIP,
				Port: portCandidate.Port,
			}
			udpConn, err := r.Calls.ListenUDP("udp", eaddr)
			if err == nil {
				stop()
				r.addUDPConn(laddr, eaddr, raddr, udpConn)
				return udpConn, nil
			}
		}
	}
	return nil, NoPorts
}

func (r *Router) forwardLANPacket(packet gopacket.Packet) (bool, error) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if udpLayer != nil && (ipv4Layer != nil || ipv6Layer != nil) {
		udp := udpLayer.(*layers.UDP)
		laddr := &net.UDPAddr{Port: int(udp.SrcPort)}
		raddr := &net.UDPAddr{Port: int(udp.DstPort)}
		if ipv4Layer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)
			laddr.IP = ipv4.SrcIP
			raddr.IP = ipv4.DstIP
		} else {
			ipv6 := ipv6Layer.(*layers.IPv6)
			laddr.IP = ipv6.SrcIP
			raddr.IP = ipv6.DstIP
		}
		return true, r.forwardLANUDPPacket(laddr, raddr, udp.Payload)
	}
	return false, nil
}

func (r *Router) forwardLANUDPPacket(laddr, raddr *net.UDPAddr, payload []byte) error {
	conn, found := r.connectionsByMapping[r.Configuration.GetMapping(laddr, raddr)]
	if !found {
		var err error
		conn, err = r.udpNewConn(laddr, raddr)
		if err != nil {
			return err
		}
	}
	for pos := 0; pos < len(payload); {
		n, err := conn.WriteToUDP(payload[pos:], raddr)
		if err != nil {
			return err
		}
		pos += n
	}
	return nil
}

type DefaultCalls struct{}

var defaultCalls = &DefaultCalls{}

func (r *DefaultCalls) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}
func (r *DefaultCalls) ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error) {
	return net.ListenUDP(network, laddr)
}
