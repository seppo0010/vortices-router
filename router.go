package main

import (
	"fmt"
	"net"
)

type Router struct {
	Configuration *Configuration
	LANInterfaces []string
	LANQueues     []int
	WANInterfaces []string
	WANQueues     []int

	// WANIPAddresses contain a list of IPs on each LAN Interface, these might be IPv4 or IPv6
	WANIPAddresses [][]net.IP
}

func NewRouter(conf *Configuration, lanInterfaces []string, lanQueues []int, wanInterfaces []string, wanQueues []int) (*Router, error) {
	var err error
	router := &Router{
		Configuration: conf,
		LANInterfaces: lanInterfaces,
		WANInterfaces: wanInterfaces,
		LANQueues:     lanQueues,
		WANQueues:     wanQueues,
	}
	router.WANIPAddresses, err = router.findLocalIPAddresses()
	return router, err
}

func (r *Router) findLocalIPAddresses() ([][]net.IP, error) {
	ifaces, err := net.Interfaces()
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

func (r *Router) Run() {
	panic("unimplemented")
}

func (r *Router) udpFindNewLAddrForRAddr(raddr *net.UDPAddr) (*net.UDPAddr, error) {
	panic("unimplemented")
}
