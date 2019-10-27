package mapping

import (
	"testing"

	"github.com/seppo0010/vortices-router/tests"
	"github.com/stretchr/testify/require"
)

func TestMappingEndpointIndependentReuse(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{NumberOfInternetComputers: 1, RouterConfig: `{"MappingType": 0}`})
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerLANIPAddress := topology.GetRouterLANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	internetComputerIPAddress2 := topology.GetInternetComputerIPAddressIndex(0)

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress.String())

	topology.StartTCPDump()

	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress2, 8000, 12345, 1)

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress2, DstPort: 8000, Payload: []byte("\n")},
	})
}

func TestMappingAddressDependentReuse(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{RouterConfig: `{"MappingType": 1}`})
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerLANIPAddress := topology.GetRouterLANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress.String())

	topology.StartTCPDump()

	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8001, 12345, 1)

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8001, Payload: []byte("\n")},
	})
}

func TestMappingAddressDependentNoReuse(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{NumberOfInternetComputers: 1, RouterConfig: `{"MappingType": 1}`})
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerLANIPAddress := topology.GetRouterLANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	internetComputerIPAddress2 := topology.GetInternetComputerIPAddressIndex(0)

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress.String())

	topology.StartTCPDump()

	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress2, 8000, 12345, 1)

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12347, DstIP: internetComputerIPAddress2, DstPort: 8000, Payload: []byte("\n")},
	})
}

func TestMappingAddressAndPortDependentReuse(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{RouterConfig: `{"MappingType": 2}`})
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerLANIPAddress := topology.GetRouterLANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress.String())

	topology.StartTCPDump()

	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
	})
}

func TestMappingAddressAndPortDependentNoReuse(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{NumberOfInternetComputers: 1, RouterConfig: `{"MappingType": 2}`})
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerLANIPAddress := topology.GetRouterLANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	internetComputerIPAddress2 := topology.GetInternetComputerIPAddressIndex(0)

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress.String())

	topology.StartTCPDump()

	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8001, 12345, 1)
	_ = topology.LANComputer.ReadEchoServer(internetComputerIPAddress2, 8000, 12345, 1)

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12347, DstIP: internetComputerIPAddress, DstPort: 8001, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12349, DstIP: internetComputerIPAddress2, DstPort: 8000, Payload: []byte("\n")},
	})
}
