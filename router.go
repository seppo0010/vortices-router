package main

import (
	"errors"
	"fmt"
	"net"
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
	WANIPAddresses [][]net.IP
	Calls
}

func NewRouter(conf *Configuration, lanInterfaces []string, lanQueues []int, wanInterfaces []string, wanQueues []int) (*Router, error) {
	var err error
	router := &Router{
		Configuration: conf,
		LANInterfaces: lanInterfaces,
		WANInterfaces: wanInterfaces,
		LANQueues:     lanQueues,
		WANQueues:     wanQueues,
		Calls:         defaultCalls,
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

func (r *Router) udpNewConn(laddr *net.UDPAddr, raddr *net.UDPAddr) (UDPConn, error) {
	wanIPs := r.wanIPsForLANIP(laddr.IP)
	portCandidates, stop := r.Configuration.GetExternalPortForInternalPort(raddr.Port)
	for portCandidate := range portCandidates {
		for _, wanIP := range wanIPs {
			// TODO: handle portCandidate.Force
			udpConn, err := r.Calls.ListenUDP("udp", &net.UDPAddr{
				IP:   wanIP,
				Port: portCandidate.Port,
			})
			if err == nil {
				stop()
				return udpConn, nil
			}
		}
	}
	return nil, NoPorts
}

type DefaultCalls struct{}

var defaultCalls = &DefaultCalls{}

func (r *DefaultCalls) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}
func (r *DefaultCalls) ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error) {
	return net.ListenUDP(network, laddr)
}
