package main

import "net"

func Hosts(cidr string) (ip_ <-chan string, exit_ chan<- interface{}) {
	inc := func(ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}
	// inspired in https://gist.github.com/kotakanbe/d3059af990252ba89a82
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err.Error())
	}

	ipChan := make(chan string)
	exitChan := make(chan interface{})
	go func() {
		ip := ip.Mask(ipnet.Mask)
		for inc(ip); ipnet.Contains(ip); inc(ip) {
			select {
			case ipChan <- ip.String():
			case <-exitChan:
				close(ipChan)
				return
			}
		}
		close(ipChan)
		<-exitChan
	}()
	return ipChan, exitChan
}
