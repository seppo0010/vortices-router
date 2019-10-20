package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/seppo0010/nfqueue-go/nfqueue"
	log "github.com/sirupsen/logrus"
)

// ErrNoPorts no port is available
var ErrNoPorts = errors.New("no available ports")

type routerQueue struct {
	router   *Router
	queueNum int
}

var routers sync.Map

// Router forwarding LAN-WAN connections.
type Router struct {
	Configuration *Configuration
	LANInterfaces []string
	LANQueues     []int
	LANAddresses  []net.HardwareAddr
	WANInterfaces []string

	// WANIPAddresses contain a list of IPs on each LAN Interface, these might be IPv4 or IPv6
	WANIPAddresses                [][]net.IP
	connectionsByMapping          map[string]*UDPConnContext
	connectionsByInternalEndpoint map[string]*UDPConnContext
	Calls
}

// UDPConnContext a connection context with the metadata to keep alive.
type UDPConnContext struct {
	UDPConn
	internalAddr  net.Addr
	externalAddrs []net.Addr
	internalMAC   net.HardwareAddr
	interfaceMAC  net.HardwareAddr
	lanInterface  string
	lastOutbound  time.Time
	lastInbound   time.Time
}

func netAddrIPPortAndProtocol(addr net.Addr) (net.IP, int, string) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.IP, udpAddr.Port, "udp"
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP, tcpAddr.Port, "tcp"
	}
	panic(fmt.Sprintf("unexpected net addr type, got %T", addr))
}

// NewRouter creates a router.
func NewRouter(conf *Configuration, lanInterfaces []string, lanQueues []int, lanAddresses []net.HardwareAddr, wanInterfaces []string) (*Router, error) {
	var err error
	router := &Router{
		Configuration:                 conf,
		LANInterfaces:                 lanInterfaces,
		WANInterfaces:                 wanInterfaces,
		LANQueues:                     lanQueues,
		LANAddresses:                  lanAddresses,
		Calls:                         defaultCalls,
		connectionsByMapping:          map[string]*UDPConnContext{},
		connectionsByInternalEndpoint: map[string]*UDPConnContext{},
	}
	router.WANIPAddresses, err = router.FindLocalIPAddresses()
	return router, err
}

func real_callback(queue *nfqueue.Queue, payload *nfqueue.Payload, sourceAddr net.HardwareAddr) int {
	rq, _ := routers.Load(queue)
	r := rq.(routerQueue).router
	queueNum := rq.(routerQueue).queueNum
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)

	forwarded, err := r.forwardLANPacket(queueNum, packet, sourceAddr)
	if err != nil {
		log.WithFields(log.Fields{
			"queue": queueNum,
			"error": err,
		}).Errorf("error forwarding packet")
		payload.SetVerdict(nfqueue.NF_ACCEPT)
	} else if forwarded {
		payload.SetVerdict(nfqueue.NF_DROP)
	} else {
		payload.SetVerdict(nfqueue.NF_ACCEPT)
	}
	return 0
}

// Run receives all incoming connections and forwards them as required.
func (r *Router) Run() {
	var wg sync.WaitGroup
	for _, lanQueue := range r.LANQueues {
		wg.Add(1)
		go func(queueNum int) {
			defer wg.Done()
			q := new(nfqueue.Queue)
			routers.Store(q, routerQueue{
				router:   r,
				queueNum: queueNum,
			})
			q.SetCallback(real_callback)
			q.Init()
			q.Unbind(syscall.AF_INET)
			q.Bind(syscall.AF_INET)
			q.CreateQueue(queueNum)
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt)
			go func() {
				for sig := range c {
					// sig is a ^C, handle it
					_ = sig
					q.StopLoop()
				}
			}()
			q.Loop()
			q.DestroyQueue()
			q.Close()
		}(lanQueue)
	}
	wg.Wait()
}

func (r *Router) wanIPsForLANIP(lanIP net.IP) []net.IP {
	if len(r.WANIPAddresses) == 1 {
		return r.WANIPAddresses[0]
	}
	return r.WANIPAddresses[r.Configuration.IPAddressPooling.GetIndexForIP(lanIP)]
}

// FindLocalIPAddresses finds IP addresses in WAN interfaces. Notice that one WAN interface
// may hold more than one IP address (e.g.: IPv4 and IPv6). The order in `WANInterfaces` is the
// order used for the IP addresses.
func (r *Router) FindLocalIPAddresses() ([][]net.IP, error) {
	ifaces, err := r.Calls.Interfaces()
	if err != nil {
		return nil, err
	}
	ipAddresses := make([][]net.IP, len(r.WANInterfaces))
	for i := range ipAddresses {
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

func (r *Router) forwardWANUDPPacket(cont *UDPConnContext, raddr net.Addr, message []byte) error {
	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	internalAddrIP, internalAddrPort, _ := netAddrIPPortAndProtocol(cont.internalAddr)
	isIPv6 := internalAddrIP.To4() == nil
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

	raddrIP, raddrPort, _ := netAddrIPPortAndProtocol(raddr)
	if !isIPv6 {
		ip = &layers.IPv4{
			SrcIP:    raddrIP,
			DstIP:    internalAddrIP,
			Protocol: layers.IPProtocolUDP,
			Version:  4,
			TTL:      32,
		}
	} else {
		ip = &layers.IPv6{
			SrcIP:      raddrIP,
			DstIP:      internalAddrIP,
			NextHeader: layers.IPProtocolUDP,
			Version:    6,
			HopLimit:   32,
		}
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(raddrPort),
		DstPort: layers.UDPPort(internalAddrPort),
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

func (r *Router) processUDPConnOnce(cont *UDPConnContext) bool {
	err := cont.UDPConn.SetReadDeadline(r.Now(NowUsageReadDeadline).Add(r.Configuration.MappingRefresh))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("error setting deadline")
		return true
	}

	buf := make([]byte, 1500)
	read, raddr, err := cont.UDPConn.ReadFromUDP(buf)
	if err != nil {
		if netError, ok := err.(net.Error); ok && netError.Timeout() {
			return false
		}
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("error reading udp conn")
		return true
	}
	cont.lastInbound = r.Now(NowUsageInbound)
	if raddr == nil {
		return true
	}

	knownRaddrs := []net.Addr{}
	for _, addr := range cont.externalAddrs {
		knownRaddrs = append(knownRaddrs, addr)
	}
	if !r.Configuration.Filtering.ShouldAccept(raddr, knownRaddrs) {
		log.WithFields(log.Fields{"raddr": raddr.String()}).Info("filtering packet")
		return true
	}
	err = r.forwardWANUDPPacket(cont, raddr, buf[:read])
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("error forwarding udp packet")
		return true
	}
	return true
}

func (r *Router) shouldEvict(cont *UDPConnContext) bool {
	if r.Configuration.OutboundRefreshBehavior && cont.lastOutbound.Add(r.Configuration.MappingRefresh).Sub(r.Now(NowUsageOutboundEvict)).Seconds() > 0 {
		return false
	}

	if r.Configuration.InboundRefreshBehavior && cont.lastInbound.Add(r.Configuration.MappingRefresh).Sub(r.Now(NowUsageInboundEvict)).Seconds() > 0 {
		return false
	}
	return true
}

func (r *Router) evictUDPConn(cont *UDPConnContext) error {
	err := cont.UDPConn.Close()
	if err != nil {
		log.Errorf("failed to close udp connection: %s", err.Error())
		return err
	}

	laddr := cont.internalAddr
	for _, raddr := range cont.externalAddrs {
		mapping := r.Configuration.GetMapping(laddr, raddr)
		if existingConn, found := r.connectionsByMapping[mapping]; found {
			existingConn.Close()
		}
		delete(r.connectionsByMapping, mapping)
	}

	internalEndpoint := laddr.String()
	delete(r.connectionsByInternalEndpoint, internalEndpoint)
	return nil
}

func (r *Router) initUDPConn(laddr, raddr net.Addr, internalMAC, interfaceMAC net.HardwareAddr, lanInterface string, udpConn UDPConn) *UDPConnContext {
	cont := &UDPConnContext{
		UDPConn:       udpConn,
		internalAddr:  laddr,
		externalAddrs: []net.Addr{raddr},
		internalMAC:   internalMAC,
		interfaceMAC:  interfaceMAC,
		lanInterface:  lanInterface,
		lastOutbound:  r.Now(NowUsageInitOutbound),
		lastInbound:   r.Now(NowUsageInitInbound),
	}
	go func() {
		for {
			if !r.processUDPConnOnce(cont) {
				// read timed out, check if we should stop
				// it is possible that we do not have to if we have written something and OutboundRefreshBehavior is true
				if r.shouldEvict(cont) {
					r.evictUDPConn(cont)
					break
				}
			}
		}
	}()
	return cont
}

func (r *Router) addUDPConn(laddr, raddr net.Addr, udpConn *UDPConnContext) {
	mapping := r.Configuration.GetMapping(laddr, raddr)
	if existingConn, found := r.connectionsByMapping[mapping]; found {
		existingConn.Close()
	}
	r.connectionsByMapping[mapping] = udpConn

	internalEndpoint := laddr.String()
	r.connectionsByInternalEndpoint[internalEndpoint] = udpConn
}

func (r *Router) udpNewConn(laddr, raddr *net.UDPAddr, internalMAC, interfaceMAC net.HardwareAddr, lanInterface string) (*UDPConnContext, error) {
	wanIPs := r.wanIPsForLANIP(laddr.IP)
	contiguityPreference := make([]int, 0, 2)
	if conn, found := r.connectionsByInternalEndpoint[(&net.UDPAddr{
		IP:   laddr.IP,
		Port: laddr.Port - 1,
	}).String()]; found {
		contiguityPreference = append(contiguityPreference, conn.LocalAddr().(*net.UDPAddr).Port+1)
	}
	if conn, found := r.connectionsByInternalEndpoint[(&net.UDPAddr{
		IP:   laddr.IP,
		Port: laddr.Port + 1,
	}).String()]; found {
		contiguityPreference = append(contiguityPreference, conn.LocalAddr().(*net.UDPAddr).Port-1)
	}
	portCandidates, stop := r.Configuration.GetExternalPortForInternalPort(laddr.Port, contiguityPreference)
	for portCandidate := range portCandidates {
		for _, wanIP := range wanIPs {
			eaddr := &net.UDPAddr{
				IP:   wanIP,
				Port: portCandidate.Port,
			}

			if portCandidate.Force {
				if conn, found := r.connectionsByInternalEndpoint[eaddr.String()]; found {
					_ = r.evictUDPConn(conn)
				}
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
	return nil, ErrNoPorts
}

func (r *Router) forwardLANPacket(queue int, packet gopacket.Packet, sourceAddr net.HardwareAddr) (bool, error) {
	lanInterface := ""
	var dstMAC net.HardwareAddr
	for i, q := range r.LANQueues {
		if q == queue {
			lanInterface = r.LANInterfaces[i]
			dstMAC = r.LANAddresses[i]
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

	if udpLayer != nil && (ipv4Layer != nil || ipv6Layer != nil) {
		udp := udpLayer.(*layers.UDP)
		laddr := &net.UDPAddr{Port: int(udp.SrcPort)}
		raddr := &net.UDPAddr{Port: int(udp.DstPort)}
		srcMAC := sourceAddr
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
	conn.lastOutbound = r.Now(NowUsageOutbound)
	return nil
}
