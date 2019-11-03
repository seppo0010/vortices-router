package ipaddresspooling

import (
	"net"
	"testing"

	"github.com/seppo0010/vortices-router/tests"
	"github.com/stretchr/testify/require"
)

func TestPoolingPaired(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{NumberOfRouterIPAddresses: 2, NumberOfLANComputers: 2})

	err := topology.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerWANIPAddress2 := net.ParseIP(topology.Router.GetIPAddresses("eth0")[1])
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()

	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	topology.LANComputers[0].ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	topology.LANComputers[1].ReadEchoServer(internetComputerIPAddress, 8001, 12346, 1)
	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12347, 1)
	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	topology.LANComputers[0].ReadEchoServer(internetComputerIPAddress, 8000, 12348, 1)
	topology.LANComputers[0].ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress2, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12346, DstIP: internetComputerIPAddress, DstPort: 8001, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12347, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress2, SrcPort: 12348, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress2, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
	})
}

func TestPoolingArbitrary(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{NumberOfRouterIPAddresses: 2, NumberOfLANComputers: 2, RouterConfig: `{"IPAddressPooling":{"seed": 1234}}`})

	err := topology.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerWANIPAddress2 := net.ParseIP(topology.Router.GetIPAddresses("eth0")[1])
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()

	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	topology.LANComputers[0].ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	topology.LANComputers[1].ReadEchoServer(internetComputerIPAddress, 8001, 12346, 1)
	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12347, 1)
	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	topology.LANComputers[0].ReadEchoServer(internetComputerIPAddress, 8000, 12348, 1)
	topology.LANComputers[0].ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)
	topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 1)

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress2, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress2, SrcPort: 12346, DstIP: internetComputerIPAddress, DstPort: 8001, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12347, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12348, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress2, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
	})
}
