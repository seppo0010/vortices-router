package main

import "time"

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
type IPAddressPooling int

const (
	// IPAddressPoolingPaired will pair any internal IP address to one external IP address and will
	// always use the same one.
	IPAddressPoolingPaired IPAddressPooling = iota
	// IPAddressPoolingArbitrary makes no guarantee about the external IP address that will be use
	// for an internal IP address.
	IPAddressPoolingArbitrary
)

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
type Filtering int

const (
	// FilteringEndpointIndependent allows any incoming packet to a registered endpoint to go
	// through.
	FilteringEndpointIndependent = iota
	// FilteringAddressDependent allows any incoming packet to a registered endpoint to go
	// through if and only if the local endpoint has sent a packet to that host.
	FilteringAddressDependent
	// FilteringAddressAndPortDependent allows any incoming packet to a registered endpoint to go
	// through if and only if the local endpoint has sent a packet to that host and port.
	FilteringAddressAndPortDependent
)

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
func DefaultConfiguration() *Configuration {
	return NewConfiguration(
		MappingTypeEndpointIndependent,
		IPAddressPoolingPaired,
		[]PortAssignment{PortAssignmentPreservation, PortAssignmentRangePreservation, PortAssignmentNoPreservation},
		true,
		true,
		2*time.Minute,
		true,
		false,
		FilteringEndpointIndependent,
		true,
	)
}
