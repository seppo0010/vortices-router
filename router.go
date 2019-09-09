package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

var NoPorts = errors.New("no available ports")

type Calls interface {
	Interfaces() ([]net.Interface, error)
	ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error)
	OpenInterface(device string) (InterfaceHandle, error)
}
type Router struct {
	Configuration *Configuration
	LANInterfaces []string
	LANQueues     []int
	WANInterfaces []string
	WANQueues     []int

	// WANIPAddresses contain a list of IPs on each LAN Interface, these might be IPv4 or IPv6
	WANIPAddresses                [][]net.IP
	connectionsByMapping          map[string]*UDPConnContext
	connectionsByInternalEndpoint map[string]*UDPConnContext
	connectionsByExternalEndpoint map[string][]*UDPConnContext
	connectionsByRemoteEndpoint   map[string][]*UDPConnContext
	Calls
}

type UDPConnContext struct {
	UDPConn
	internalAddr  *net.UDPAddr
	externalAddrs []*net.UDPAddr
	internalMAC   net.HardwareAddr
	interfaceMAC  net.HardwareAddr
	lanInterface  string
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
		connectionsByMapping:          map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string]*UDPConnContext{},
		connectionsByExternalEndpoint: map[string][]*UDPConnContext{},
		connectionsByRemoteEndpoint:   map[string][]*UDPConnContext{},
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

func (r *Router) forwardWANUDPPacket(cont *UDPConnContext, raddr *net.UDPAddr, message []byte) error {
	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	isIPv6 := cont.internalAddr.IP.To4() == nil
	ethernetType := layers.EthernetTypeIPv4
	if isIPv6 {
		ethernetType = layers.EthernetTypeIPv6
	}
	eth := &layers.Ethernet{
		SrcMAC:       cont.interfaceMAC,
		DstMAC:       cont.internalMAC,
		EthernetType: ethernetType,
	}

	var ip interface {
		gopacket.NetworkLayer
		SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error
	}

	if !isIPv6 {
		ip = &layers.IPv4{
			SrcIP:    raddr.IP,
			DstIP:    cont.internalAddr.IP,
			Protocol: layers.IPProtocolUDP,
			Version:  4,
			TTL:      32,
		}
	} else {
		ip = &layers.IPv6{
			SrcIP:      raddr.IP,
			DstIP:      cont.internalAddr.IP,
			NextHeader: layers.IPProtocolUDP,
			Version:    6,
			HopLimit:   32,
		}
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(raddr.Port),
		DstPort: layers.UDPPort(cont.internalAddr.Port),
	}
	udp.SetNetworkLayerForChecksum(ip)
	err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip, udp, gopacket.Payload(message))
	if err != nil {
		return err
	}

	handle, err := r.Calls.OpenInterface(cont.lanInterface)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	return handle.WritePacketData(buf.Bytes())
}

func (r *Router) initUDPConn(laddr, raddr *net.UDPAddr, internalMAC, interfaceMAC net.HardwareAddr, lanInterface string, udpConn UDPConn) *UDPConnContext {
	cont := &UDPConnContext{
		UDPConn:       udpConn,
		internalAddr:  laddr,
		externalAddrs: []*net.UDPAddr{raddr},
		internalMAC:   internalMAC,
		interfaceMAC:  interfaceMAC,
		lanInterface:  lanInterface,
	}
	go func() {
		for {
			buf := make([]byte, 1500)
			read, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Error("error reading udp conn")
				continue
			}
			// TODO: configuration filtering
			// TODO: stop the goroutine at some point
			err = r.forwardWANUDPPacket(cont, raddr, buf[:read])
			if err != nil {
				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Error("error forwarding udp packet")
				continue
			}
		}

	}()
	return cont
}

func (r *Router) addUDPConn(laddr, raddr *net.UDPAddr, udpConn *UDPConnContext) {
	mapping := r.Configuration.GetMapping(laddr, raddr)
	if existingConn, found := r.connectionsByMapping[mapping]; found {
		existingConn.Close()
	}
	r.connectionsByMapping[mapping] = udpConn

	internalEndpoint := laddr.String()
	r.connectionsByInternalEndpoint[internalEndpoint] = udpConn

	externalEndpoint := udpConn.LocalAddr().String()
	if _, found := r.connectionsByExternalEndpoint[externalEndpoint]; !found {
		r.connectionsByExternalEndpoint[externalEndpoint] = []*UDPConnContext{}
	}
	r.connectionsByExternalEndpoint[externalEndpoint] = append(r.connectionsByExternalEndpoint[externalEndpoint], udpConn)

	remoteEndpoint := raddr.String()
	if _, found := r.connectionsByRemoteEndpoint[remoteEndpoint]; !found {
		r.connectionsByRemoteEndpoint[remoteEndpoint] = []*UDPConnContext{}
	}
	r.connectionsByRemoteEndpoint[remoteEndpoint] = append(r.connectionsByRemoteEndpoint[remoteEndpoint], udpConn)
}

func (r *Router) udpNewConn(laddr, raddr *net.UDPAddr, internalMAC, interfaceMAC net.HardwareAddr, lanInterface string) (*UDPConnContext, error) {
	wanIPs := r.wanIPsForLANIP(laddr.IP)
	contiguityPreference := make([]int, 0, 2)
	if cont, found := r.connectionsByInternalEndpoint[(&net.UDPAddr{
		IP:   laddr.IP,
		Port: laddr.Port - 1,
	}).String()]; found {
		contiguityPreference = append(contiguityPreference, cont.LocalAddr().(*net.UDPAddr).Port+1)
	}
	if cont, found := r.connectionsByInternalEndpoint[(&net.UDPAddr{
		IP:   laddr.IP,
		Port: laddr.Port + 1,
	}).String()]; found {
		contiguityPreference = append(contiguityPreference, cont.LocalAddr().(*net.UDPAddr).Port-1)
	}
	portCandidates, stop := r.Configuration.GetExternalPortForInternalPort(laddr.Port, contiguityPreference)
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
				connContext := r.initUDPConn(laddr, raddr, internalMAC, interfaceMAC, lanInterface, udpConn)
				r.addUDPConn(laddr, raddr, connContext)
				return connContext, nil
			}
		}
	}
	return nil, NoPorts
}

func (r *Router) forwardLANPacket(queue int, packet gopacket.Packet) (bool, error) {
	lanInterface := ""
	for i, q := range r.LANQueues {
		if q == queue {
			lanInterface = r.LANInterfaces[i]
			break
		}
	}
	if lanInterface == "" {
		log.WithFields(log.Fields{"queue": queue}).Error("unable to find lan interface for queue")
		return false, nil
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if udpLayer != nil && (ipv4Layer != nil || ipv6Layer != nil) && ethernetLayer != nil {
		udp := udpLayer.(*layers.UDP)
		laddr := &net.UDPAddr{Port: int(udp.SrcPort)}
		raddr := &net.UDPAddr{Port: int(udp.DstPort)}
		srcMAC := ethernetLayer.(*layers.Ethernet).SrcMAC
		dstMAC := ethernetLayer.(*layers.Ethernet).DstMAC
		if ipv4Layer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)
			laddr.IP = ipv4.SrcIP
			raddr.IP = ipv4.DstIP
		} else {
			ipv6 := ipv6Layer.(*layers.IPv6)
			laddr.IP = ipv6.SrcIP
			raddr.IP = ipv6.DstIP
		}
		return true, r.forwardLANUDPPacket(laddr, raddr, srcMAC, dstMAC, lanInterface, udp.Payload)
	}
	return false, nil
}

func (r *Router) forwardLANUDPPacket(laddr, raddr *net.UDPAddr, srcMAC, dstMAC net.HardwareAddr, lanInterface string, payload []byte) error {
	conn, found := r.connectionsByMapping[r.Configuration.GetMapping(laddr, raddr)]
	if !found {
		var err error
		conn, err = r.udpNewConn(laddr, raddr, srcMAC, dstMAC, lanInterface)
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

type InterfaceHandle interface {
	Close()
	WritePacketData(data []byte) (err error)
}

type DefaultCalls struct{}

var defaultCalls = &DefaultCalls{}

func (r *DefaultCalls) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}
func (r *DefaultCalls) ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error) {
	return net.ListenUDP(network, laddr)
}

func (r *DefaultCalls) OpenInterface(device string) (InterfaceHandle, error) {
	return pcap.OpenLive(device, 1024, false, pcap.BlockForever)
}
