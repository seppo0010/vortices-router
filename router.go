package main

import "time"

type MappingType int

const (
	MappingTypeEndpointIndependent MappingType = iota
	MappingTypeAddressDependent
	MappingTypeAddressAndPortDependent
)

type IPAddressPooling int

const (
	IPAddressPoolingPaired IPAddressPooling = iota
	IPAddressPoolingArbitrary
)

type PortAssignment int

const (
	PortAssignmentPreservation PortAssignment = iota
	PortAssignmentOverloading
	PortAssignmentRangePreservation
	PortAssignmentNoPreservation
)

type Filtering int

const (
	FilteringEndpointIndependent = iota
	FilteringAddressDependent
	FilteringAddressAndPortDependent
)

type Configuration struct {
	MappingType             MappingType
	IPAddressPooling        IPAddressPooling
	PortAssignment          PortAssignment
	PortPreservationParity  bool
	PortContiguity          bool
	MappingRefresh          time.Duration
	OutboundRefreshBehavior bool
	InboundRefreshBehavior  bool
	Filtering               Filtering
	Hairpinning             bool
}

func NewConfiguration(
	mappingType MappingType,
	ipAddressPooling IPAddressPooling,
	portAssignment PortAssignment,
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

func DefaultConfiguration() *Configuration {
	return NewConfiguration(
		MappingTypeEndpointIndependent,
		IPAddressPoolingPaired,
		PortAssignmentPreservation,
		true,
		true,
		2*time.Minute,
		true,
		false,
		FilteringEndpointIndependent,
		true,
	)
}

func main() {}
