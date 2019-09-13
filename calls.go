package main

import (
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

// NowUsage purpose of the now call. Useful for mocking.
type NowUsage int

const (
	// NowUsageInitInbound timestamp for last inbound for new udp connection
	NowUsageInitInbound NowUsage = iota
	// NowUsageInitOutbound timestamp for last outbound for new udp connection
	NowUsageInitOutbound
	// NowUsageInbound timestamp after an inbound message is executed
	NowUsageInbound
	// NowUsageOutbound timestamp after an outbound message is executed
	NowUsageOutbound
	// NowUsageReadDeadline timestamp for network read timeout
	NowUsageReadDeadline
	// NowUsageOutboundEvict timestamp when validating expiration of outbound connections
	NowUsageOutboundEvict
	// NowUsageInboundEvict timestamp when validating expiration of inbound connections
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
