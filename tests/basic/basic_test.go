package basic

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/seppo0010/vortices-router/tests"
	"github.com/stretchr/testify/require"
)

func TestBasic(t *testing.T) {
	topology := tests.NewTopology(t)
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()

	routerWANIPAddress, err := topology.Router.GetIPAddressForNetwork(topology.Internet)
	require.Nil(t, err)
	lanComputerIPAddress, err := topology.LANComputer.GetIPAddressForNetwork(topology.LAN)
	require.Nil(t, err)
	internetComputerIPAddress, err := topology.InternetComputer.GetIPAddressForNetwork(topology.Internet)
	require.Nil(t, err)
	routerLANIPAddress, err := topology.Router.GetIPAddressForNetwork(topology.LAN)
	require.Nil(t, err)

	topology.LANComputer.SetDefaultGateway(routerLANIPAddress)

	topology.StartTCPDump()

	server := topology.InternetComputer.Exec("bash", "-c", "echo hello |nc -u -l 8000 -W 1 -v")
	serverOut, _ := server.StdoutPipe()
	err = server.Start()
	require.Nil(t, err)
	defer func() {
		server.Kill()
	}()
	serverOutBuffered := bufio.NewReader(serverOut)
	line, _, err := serverOutBuffered.ReadLine()
	expected := "Listening on"
	if !strings.HasPrefix(string(line), expected) {
		t.Fatalf("expected buffer (%s) to be (%s)", string(line), string(expected))
	}

	cmd := topology.LANComputer.Exec("bash", "-c", fmt.Sprintf("echo ''| nc %s 8000 -p 12345 -u -W 1", internetComputerIPAddress))
	stdoutPipe, err := cmd.StdoutPipe()
	require.Nil(t, err)
	err = cmd.Start()
	require.Nil(t, err)
	stdout := []byte{}
	done := make(chan bool)
	go func() {
		stdout, err = ioutil.ReadAll(stdoutPipe)
		done <- true
	}()
	select {
	case <-time.After(3 * time.Second):
		t.Error("timed out")
	case <-done:
	}

	require.Nil(t, err)
	require.Equal(t, string(stdout), "hello\n")

	topology.ValidateSteps([]tests.Step{
		tests.Step{Service: "lancomputer", SrcIP: net.ParseIP(lanComputerIPAddress), SrcPort: 12345, DstIP: net.ParseIP(internetComputerIPAddress), DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: net.ParseIP(lanComputerIPAddress), SrcPort: 12345, DstIP: net.ParseIP(internetComputerIPAddress), DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "router", SrcIP: net.ParseIP(routerWANIPAddress), SrcPort: 12345, DstIP: net.ParseIP(internetComputerIPAddress), DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", SrcIP: net.ParseIP(routerWANIPAddress), SrcPort: 12345, DstIP: net.ParseIP(internetComputerIPAddress), DstPort: 8000, Payload: []byte("\n")},
		tests.Step{Service: "internetcomputer", DstIP: net.ParseIP(routerWANIPAddress), DstPort: 12345, SrcIP: net.ParseIP(internetComputerIPAddress), SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "router", DstIP: net.ParseIP(routerWANIPAddress), DstPort: 12345, SrcIP: net.ParseIP(internetComputerIPAddress), SrcPort: 8000, Payload: []byte("hello\n")},
		tests.Step{Service: "lancomputer", DstIP: net.ParseIP(lanComputerIPAddress), DstPort: 12345, SrcIP: net.ParseIP(internetComputerIPAddress), SrcPort: 8000, Payload: []byte("hello\n")},
	})

	topology.PrintDebugIfFailed()
}
