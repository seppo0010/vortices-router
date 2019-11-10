package ipaddresspooling

import (
	"testing"

	"github.com/seppo0010/vortices-router/tests"
	"github.com/stretchr/testify/require"
)

func TestFilteringEndpointIndependent(t *testing.T) {
    topology := tests.NewTopology(t, &tests.TopologyConfiguration{NumberOfInternetComputers: 1})

	err := topology.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	lanComputerIPAddress := topology.GetLANComputerIPAddress()
	routerWANIPAddress := topology.GetRouterWANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
    internetComputerIPAddress2 := topology.GetInternetComputerIPAddressIndex(0)

	topology.LANComputer.ReadEchoServer(internetComputerIPAddress2, 1, 2, 0)
	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 22456, 1)
	topology.InternetComputers[0].ReadEchoServer(routerWANIPAddress, 22456, 29876, 1)

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 22456, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: internetComputerIPAddress2, SrcPort: 29876, DstIP: routerWANIPAddress, DstPort: 22456, Payload: []byte("\n")},
		tests.Step{Service: "lancomputer", SrcIP: internetComputerIPAddress2, SrcPort: 29876, DstIP: lanComputerIPAddress, DstPort: 22456, Payload: []byte("\n")},
	})
}
func TestFilteringAddressDependent(t *testing.T) {
    t.Error("unimplemented")
}

func TestFilteringAddressAndPortDependent(t *testing.T) {
    t.Error("unimplemented")
}
