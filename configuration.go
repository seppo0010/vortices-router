package main

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// MappingType establishes what destination headers are considered when choosing to reuse an
// outgoing endpoint.
type MappingType int

const (
	// MappingTypeEndpointIndependent will reuse the same outgoing endpoint for any destination
	// while the source endpoint matches. A packet from iAddr:iPort will always use the same
	// eAddr:ePort
	MappingTypeEndpointIndependent MappingType = iota
	// MappingTypeAddressDependent will reuse the same outgoing endpoint for any destination
	// while the source endpoint and the destination host matches. A packet from iAddr:iPort will
	// use the same eAddr:ePort of and only if hAddr is the same.
	MappingTypeAddressDependent
	// MappingTypeAddressAndPortDependent will reuse the same outgoing endpoint for any destination
	// while the source endpoint and the destination endpoint matches. A packet from iAddr:iPort
	// will use the same eAddr:ePort of and only if hAddr:hPort is the same.
	MappingTypeAddressAndPortDependent
)

// IPAddressPooling determines how to use different outgoing IP addresses. This is not very common.
type IPAddressPooling interface {
	GetIndexForIP(ip net.IP) int
}

// IPAddressPoolingPaired will pair any internal IP address to one external IP address and will
// always use the same one.
type IPAddressPoolingPaired struct {
	max   int
	last  int
	pairs map[string]int
}

// NewIPAddressPoolingPaired creates an IPAddressPoolingPaired with `max` IP addresses
func NewIPAddressPoolingPaired(max int) *IPAddressPoolingPaired {
	return &IPAddressPoolingPaired{
		last:  -1,
		max:   max,
		pairs: map[string]int{},
	}
}

// GetIndexForIP gets the WAN IP address index to user for a LAN IP address. The same LAN IP
// address will always return the same index.
func (p *IPAddressPoolingPaired) GetIndexForIP(ip net.IP) int {
	ipString := ip.String()
	if val, found := p.pairs[ipString]; found {
		return val
	}
	p.last = (p.last + 1) % p.max
	p.pairs[ipString] = p.last
	return p.last
}

// IPAddressPoolingArbitrary makes no guarantee about the external IP address that will be use
// for an internal IP address.
type IPAddressPoolingArbitrary struct {
	max        int
	randSource rand.Source
}

// GetIndexForIP gets the WAN IP address index to user for a LAN IP address. The index is always
// random.
func (p *IPAddressPoolingArbitrary) GetIndexForIP(ip net.IP) int {
	if p.randSource != nil {
		return rand.New(p.randSource).Int() % p.max
	}
	return rand.Int() % p.max
}

// PortAssignment sets the rules to handle external port assignment.
type PortAssignment int

const (
	// PortAssignmentPreservation tries to keep the outgoing local port when deciding the outgoing
	// external port
	PortAssignmentPreservation PortAssignment = iota
	// PortAssignmentPreservationOverloading will drop any existing connection using the same port
	// to honor the preservation.
	PortAssignmentPreservationOverloading
	// PortAssignmentRangePreservation mantains the range (either 0-1023 or 1024-65535) where the
	// local port was.
	PortAssignmentRangePreservation
	// PortAssignmentNoPreservation opens any outgoing port.
	PortAssignmentNoPreservation
)

// Filtering chooses which incoming packets are forwarded.
type Filtering interface {
	ShouldAccept(raddr net.Addr, knownRaddrs []net.Addr) bool
}

// FilteringEndpointIndependent allows any incoming packet to a registered endpoint to go
// through.
type FilteringEndpointIndependent struct{}

// ShouldAccept whether the incoming raddr should be accepted given that a list of `knownRaddrs`
// received an outgoing message. In this case it is always accepted.
func (f FilteringEndpointIndependent) ShouldAccept(raddr net.Addr, knownRaddrs []net.Addr) bool {
	return true
}

// FilteringAddressDependent allows any incoming packet to a registered endpoint to go
// through if and only if the local endpoint has sent a packet to that host.
type FilteringAddressDependent struct{}

// ShouldAccept whether the incoming raddr should be accepted given that a list of `knownRaddrs`
// received an outgoing message. In this case it is only accepted if the remote host was used.
func (f FilteringAddressDependent) ShouldAccept(raddr net.Addr, knownRaddrs []net.Addr) bool {
	var raddrIP, knownRaddrIP net.IP
	if raddrTCP, ok := raddr.(*net.TCPAddr); ok {
		raddrIP = raddrTCP.IP
	} else if raddrUDP, ok := raddr.(*net.UDPAddr); ok {
		raddrIP = raddrUDP.IP
	} else {
		log.WithFields(log.Fields{
			"type": fmt.Sprintf("%T", raddr),
		}).Warn("unsupported address type")
		return false
	}

	for _, knownRaddr := range knownRaddrs {
		if knownRaddrTCP, ok := knownRaddr.(*net.TCPAddr); ok {
			knownRaddrIP = knownRaddrTCP.IP
		} else if knownRaddrUDP, ok := knownRaddr.(*net.UDPAddr); ok {
			knownRaddrIP = knownRaddrUDP.IP
		} else {
			log.WithFields(log.Fields{
				"type": fmt.Sprintf("%T", knownRaddr),
			}).Warn("unsupported address type")
			continue
		}
		if raddrIP.String() == knownRaddrIP.String() {
			return true
		}
	}
	return false
}

// FilteringAddressAndPortDependent allows any incoming packet to a registered endpoint to go
// through if and only if the local endpoint has sent a packet to that host and port.
type FilteringAddressAndPortDependent struct{}

// ShouldAccept whether the incoming raddr should be accepted given that a list of `knownRaddrs`
// received an outgoing message. In this case it is only accepted if the remote host, port and
// protocol was used.
func (f FilteringAddressAndPortDependent) ShouldAccept(raddr net.Addr, knownRaddrs []net.Addr) bool {
	raddrNetwork := raddr.Network()
	raddrString := raddr.String()
	for _, knownRaddr := range knownRaddrs {
		if raddrNetwork == knownRaddr.Network() && raddrString == knownRaddr.String() {
			return true
		}
	}
	return false
}

// Configuration a router configuration.
type Configuration struct {
	MappingType      MappingType
	IPAddressPooling IPAddressPooling
	// PortAssignment is a list of rules to select a port that will be executed in order if the
	// previous one were not able to find a port.
	PortAssignment          []PortAssignment
	PortPreservationParity  bool
	PortContiguity          bool
	MappingRefresh          time.Duration
	OutboundRefreshBehavior bool
	InboundRefreshBehavior  bool
	Filtering               Filtering
	Hairpinning             bool
}

// NewConfiguration creates a Configuration
func NewConfiguration(
	mappingType MappingType,
	ipAddressPooling IPAddressPooling,
	portAssignment []PortAssignment,
	portPreservationParity bool,
	portContiguity bool,
	mappingRefresh time.Duration,
	outboundRefreshBehavior bool,
	inboundRefreshBehavior bool,
	filtering Filtering,
	hairpinning bool,
) *Configuration {
	return &Configuration{
		MappingType:             mappingType,
		IPAddressPooling:        ipAddressPooling,
		PortAssignment:          portAssignment,
		PortPreservationParity:  portPreservationParity,
		PortContiguity:          portContiguity,
		MappingRefresh:          mappingRefresh,
		OutboundRefreshBehavior: outboundRefreshBehavior,
		InboundRefreshBehavior:  inboundRefreshBehavior,
		Filtering:               filtering,
		Hairpinning:             hairpinning,
	}
}

// DefaultConfiguration creates a Configuration with the recommended settings.
func DefaultConfiguration(numWAN int) *Configuration {
	return NewConfiguration(
		MappingTypeEndpointIndependent,
		NewIPAddressPoolingPaired(numWAN),
		[]PortAssignment{PortAssignmentPreservation, PortAssignmentRangePreservation, PortAssignmentNoPreservation},
		true,
		true,
		2*time.Minute,
		true,
		false,
		FilteringEndpointIndependent{},
		true,
	)
}

// PortCandidate is a port that may be used to connect to a WAN host based on the settings'
// preferences.
type PortCandidate struct {
    // Port is the port number (0-65535)
	Port  int
    // Force is whether the candidate should be used replacing any existing connection.
    // This only happens when overloading is enabled.
	Force bool
}

// SendPortCandidate yields a port candidate to the channel if a stop message has not being
// received.
func (c *Configuration) SendPortCandidate(portCandidate PortCandidate, ch chan<- PortCandidate, stopCh chan bool) bool {
	select {
	case ch <- portCandidate:
		return true
	case <-stopCh:
		return false
	}
}

// SendPortsInRange sends all the ports from `min` to `max`, using a `step`.
func (c *Configuration) SendPortsInRange(min, max, step int, ch chan<- PortCandidate, triedPorts map[int]bool, stopCh chan bool) bool {
	for i := min; i <= max; i += step {
		if tried, _ := triedPorts[i]; tried {
			continue
		}
		triedPorts[i] = true
		if !c.SendPortCandidate(PortCandidate{Port: i}, ch, stopCh) {
			return false
		}
	}
	return true
}

// GetExternalPortForInternalPort sends port candidates to use on WAN for an outgoing LAN port based
// on the configuration preferences. A `stop` function is also provided to indicate that a candidate
// was chosen and no more are needed.
func (c *Configuration) GetExternalPortForInternalPort(internalPort int, contiguityPreference []int) (<-chan PortCandidate, func()) {
	stopCh := make(chan bool)
	stop := func() {
		stopCh <- true
	}
	ch := make(chan PortCandidate)
	go func() {
		defer close(ch)
		triedPorts := map[int]bool{}
		if c.PortContiguity && contiguityPreference != nil {
			// If port contiguity is set, should it take presedence over port preservation?
			// I think so since if port preservation was accomplished for the former port it is
			// equivalent, but if it was not it might be more important to be consistent.
			for _, port := range contiguityPreference {
				triedPorts[port] = true
				if !c.SendPortCandidate(PortCandidate{Port: port}, ch, stopCh) {
					return
				}
			}
		}
		for _, portAssignment := range c.PortAssignment {
			var min, max int
			switch portAssignment {
			case PortAssignmentPreservation:
				triedPorts[internalPort] = true
				if !c.SendPortCandidate(PortCandidate{Port: internalPort}, ch, stopCh) {
					return
				}
			case PortAssignmentPreservationOverloading:
				triedPorts[internalPort] = true
				if !c.SendPortCandidate(PortCandidate{Port: internalPort, Force: true}, ch, stopCh) {
					return
				}
			case PortAssignmentRangePreservation:
				if internalPort < 1024 {
					min = 1
					max = 1023
				} else {
					min = 1024
					max = 65535
				}
				if c.PortPreservationParity {
					minCorrection := 0
					if min%2 != internalPort%2 {
						minCorrection = 1
					}
					if !c.SendPortsInRange(internalPort, max, 2, ch, triedPorts, stopCh) || !c.SendPortsInRange(min+minCorrection, internalPort, 2, ch, triedPorts, stopCh) {
						return
					}
				}
				if !c.SendPortsInRange(internalPort, max, 1, ch, triedPorts, stopCh) || !c.SendPortsInRange(min, internalPort, 1, ch, triedPorts, stopCh) {
					return
				}
			case PortAssignmentNoPreservation:
				if c.PortPreservationParity {
					if !c.SendPortsInRange(1, 65535, 2, ch, triedPorts, stopCh) {
						return
					}
				}
				if !c.SendPortsInRange(1, 65535, 1, ch, triedPorts, stopCh) {
					return
				}
			}
		}
	}()
	return ch, stop
}

// GetMapping returns a key to index a connection based on the configuration. When the same mapping
// is returned the same external port may be used.
// For example, a full cone NAT will ignore the `raddr` and use the same port to connect to any
// external endpoint.
// An address restricted NAT will produce the same mapping if the remote hostname is the same.
func (c *Configuration) GetMapping(laddr, raddr net.Addr) string {
	switch c.MappingType {
	case MappingTypeEndpointIndependent:
		return laddr.String()
	case MappingTypeAddressDependent:
		var ip net.IP
		if tcpAddr, ok := raddr.(*net.TCPAddr); ok {
			ip = tcpAddr.IP
		} else if udpAddr, ok := raddr.(*net.UDPAddr); ok {
			ip = udpAddr.IP
		} else {
			panic(fmt.Sprintf("unsupported net.Addr for mapping: %T", raddr))
		}
		return fmt.Sprintf("%s->%s", laddr.String(), ip.String())
	case MappingTypeAddressAndPortDependent:
		return fmt.Sprintf("%s->%s", laddr.String(), raddr.String())
	}
	panic(fmt.Sprintf("unexpected mapping type: %v", c.MappingType))
}
