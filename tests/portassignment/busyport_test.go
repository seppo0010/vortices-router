package portassignment

import (
	"testing"

	"github.com/seppo0010/vortices-router/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBusyPortMaintainRange(t *testing.T) {
	topology := tests.NewTopology(t, nil)
	err := topology.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	lanComputerIPAddress := topology.GetLANComputerIPAddress()

	server := topology.InternetComputer.StartEchoServer("hello", 8000, 1)
	defer server.Kill()

	routerBusyPort := topology.Router.StartEchoServerGolang("just occupying a port", 12345, 1)
	defer routerBusyPort.Kill()

	stdout := topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 3)
	assert.Equal(t, string(stdout), "hello\n")

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "lancomputer", SrcIP: lanComputerIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: lanComputerIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12347, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", SrcIP: routerWANIPAddress, SrcPort: 12347, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", DstIP: routerWANIPAddress, DstPort: 12347, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "router", DstIP: routerWANIPAddress, DstPort: 12347, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "lancomputer", DstIP: lanComputerIPAddress, DstPort: 12345, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
	})
}

func TestBusyPortMaintainRange_BusyInRouter(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{NumberOfLANComputers: 1})
	err := topology.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	lanComputerIPAddress := topology.GetLANComputerIPAddress()

	server := topology.InternetComputer.StartEchoServer("hello", 8000, 1)
	defer server.Kill()

	// there's nothing in that dst port, just using this to get src port assigned in the router
	_ = topology.LANComputers[0].ReadEchoServer(internetComputerIPAddress, 8001, 12345, 1)

	stdout := topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 3)
	assert.Equal(t, string(stdout), "hello\n")

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "lancomputer", SrcIP: lanComputerIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: lanComputerIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12347, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", SrcIP: routerWANIPAddress, SrcPort: 12347, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", DstIP: routerWANIPAddress, DstPort: 12347, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "router", DstIP: routerWANIPAddress, DstPort: 12347, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "lancomputer", DstIP: lanComputerIPAddress, DstPort: 12345, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
	})
}

func TestBusyPort_Overloading(t *testing.T) {
	topology := tests.NewTopology(t, &tests.TopologyConfiguration{
		NumberOfLANComputers: 1,
		RouterConfig:         `{"PortAssignment":[1]}`,
	})
	err := topology.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	lanComputerIPAddress := topology.GetLANComputerIPAddress()

	server := topology.InternetComputer.StartEchoServer("hello", 8000, 1)
	defer server.Kill()

	// there's nothing in that dst port, just using this to get src port assigned in the router
	_ = topology.LANComputers[0].ReadEchoServer(internetComputerIPAddress, 8001, 12345, 1)

	stdout := topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 3)
	assert.Equal(t, string(stdout), "hello\n")

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "lancomputer", SrcIP: lanComputerIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: lanComputerIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", SrcIP: routerWANIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", DstIP: routerWANIPAddress, DstPort: 12345, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "router", DstIP: routerWANIPAddress, DstPort: 12345, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "lancomputer", DstIP: lanComputerIPAddress, DstPort: 12345, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
	})
}
