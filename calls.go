package main

import (
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

type NowUsage int

const (
	NowUsageInitRead NowUsage = iota
	NowUsageInitWrite
	NowUsageRead
	NowUsageWrite
	NowUsageReadDeadline
	NowUsageOutboundEvict
	NowUsageInboundEvict
)

// Calls operative system calls
type Calls interface {
	Interfaces() ([]net.Interface, error)
	ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error)
	OpenInterface(device string) (InterfaceHandle, error)
	Now(usage NowUsage) time.Time
}

// InterfaceHandle a handle to a network interface.
type InterfaceHandle interface {
	Close()
	WritePacketData(data []byte) (err error)
}

// DefaultCalls operative system real calls.
type DefaultCalls struct{}

var defaultCalls = &DefaultCalls{}

// Interfaces network interfaces.
func (r *DefaultCalls) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

// ListenUDP opens a port in a network interface.
func (r *DefaultCalls) ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error) {
	return net.ListenUDP(network, laddr)
}

// OpenInterface creates an interface handle to write data directly into the interface.
func (r *DefaultCalls) OpenInterface(device string) (InterfaceHandle, error) {
	return pcap.OpenLive(device, 1024, false, pcap.BlockForever)
}

// Now returns the current time
func (r *DefaultCalls) Now(usage NowUsage) time.Time {
	return time.Now()
}
