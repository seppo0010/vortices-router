package basic

import (
	"testing"

	"github.com/seppo0010/vortices-router/tests"
	"github.com/stretchr/testify/require"
)

func TestBasic(t *testing.T) {
	topology := tests.NewTopology(t, "")
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerLANIPAddress := topology.GetRouterLANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	lanComputerIPAddress := topology.GetLANComputerIPAddress()

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress.String())

	topology.StartTCPDump()

	server := topology.InternetComputer.StartEchoServer("hello", 8000, 1)
	defer server.Kill()

	stdout := topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 3)
	require.Equal(t, string(stdout), "hello\n")

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

func TestBusyPortMaintainRange(t *testing.T) {
	topology := tests.NewTopology(t, "")
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerLANIPAddress := topology.GetRouterLANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	lanComputerIPAddress := topology.GetLANComputerIPAddress()

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress.String())

	topology.StartTCPDump()

	server := topology.InternetComputer.StartEchoServer("hello", 8000, 1)
	defer server.Kill()

	routerBusyPort := topology.Router.StartEchoServerGolang("just occupying a port", 12345, 1)
	defer routerBusyPort.Kill()

	stdout := topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 3)
	require.Equal(t, string(stdout), "hello\n")

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

func TestRandomPort(t *testing.T) {
	topology := tests.NewTopology(t, `{"PortAssignment":[3]}`)
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()
	defer topology.PrintDebugIfFailed()

	routerWANIPAddress := topology.GetRouterWANIPAddress()
	routerLANIPAddress := topology.GetRouterLANIPAddress()
	internetComputerIPAddress := topology.GetInternetComputerIPAddress()
	lanComputerIPAddress := topology.GetLANComputerIPAddress()

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress.String())

	topology.StartTCPDump()

	server := topology.InternetComputer.StartEchoServer("hello", 8000, 1)
	defer server.Kill()

	stdout := topology.LANComputer.ReadEchoServer(internetComputerIPAddress, 8000, 12345, 3)
	require.Equal(t, string(stdout), "hello\n")

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "lancomputer", SrcIP: lanComputerIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: lanComputerIPAddress, SrcPort: 12345, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: routerWANIPAddress, SrcPort: 1, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", SrcIP: routerWANIPAddress, SrcPort: 1, DstIP: internetComputerIPAddress, DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", DstIP: routerWANIPAddress, DstPort: 1, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "router", DstIP: routerWANIPAddress, DstPort: 1, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "lancomputer", DstIP: lanComputerIPAddress, DstPort: 12345, SrcIP: internetComputerIPAddress, SrcPort: 8000, Payload: []byte("hello\n")},
	})
}
