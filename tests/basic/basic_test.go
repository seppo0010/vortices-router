package basic

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/btree"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	dc "github.com/seppo0010/vortices-dockercompose"
	"github.com/seppo0010/vortices-dockercompose/exec"
	"github.com/seppo0010/vortices-router/tests"
	"github.com/stretchr/testify/require"
)

type Topology struct {
	LAN              *dc.Network
	Internet         *dc.Network
	Router           *dc.Service
	LANComputer      *dc.Service
	InternetComputer *dc.Service
	Compose          *dc.Compose
}

func basicInit(t *testing.T) *Topology {
	_, filename, _, _ := runtime.Caller(1)

	compose := dc.NewCompose(dc.ComposeConfig{})
	routerImage, err := compose.BuildDockerPath("router", path.Dir(path.Dir((path.Dir(filename)))))
	require.Nil(t, err)

	topology := &Topology{Compose: compose}
	topology.LAN = compose.AddNetwork("lan", dc.NetworkConfig{})
	topology.Internet = compose.AddNetwork("internet", dc.NetworkConfig{})
	topology.Router = compose.AddService("router", dc.ServiceConfig{
		Command:    []string{"./main", "--wan-alias", "wan", "--lan-alias", "lan"},
		Image:      routerImage,
		Privileged: true,
	}, []dc.ServiceNetworkConfig{
		dc.ServiceNetworkConfig{Network: topology.LAN, Aliases: []string{"lan"}},
		dc.ServiceNetworkConfig{Network: topology.Internet, Aliases: []string{"wan"}},
	})
	computerImage, err := compose.BuildDocker("computer", `
FROM ubuntu
RUN apt update && apt install -y iproute2 netcat-openbsd iputils-ping tcpdump
    `)
	require.Nil(t, err)
	computerConfig := dc.ServiceConfig{Image: computerImage, Command: []string{"sleep", "infinity"}}
	topology.LANComputer = compose.AddService("lancomputer", computerConfig, []dc.ServiceNetworkConfig{
		dc.ServiceNetworkConfig{Network: topology.LAN},
	})
	topology.InternetComputer = compose.AddService("internetcomputer", computerConfig, []dc.ServiceNetworkConfig{
		dc.ServiceNetworkConfig{Network: topology.Internet},
	})
	return topology
}

type tcpdumpListener struct {
	cmd               exec.Cmd
	path              string
	finishedWaitGroup *sync.WaitGroup
	readyWaitGroup    *sync.WaitGroup
}

func tcpdump(t *testing.T, service *dc.Service, iface string) *tcpdumpListener {
	l := &tcpdumpListener{}
	l.cmd = service.Exec("tcpdump", "-i", iface, "-l", "--immediate-mode", "-w", "-", "udp")
	out, _ := l.cmd.StdoutPipe()
	_, _ = l.cmd.StderrPipe()
	l.cmd.Start()
	f, _ := ioutil.TempFile("", fmt.Sprintf("%s*.pcap", service.ContainerName))
	l.path = f.Name()
	l.finishedWaitGroup = &sync.WaitGroup{}
	l.finishedWaitGroup.Add(1)
	l.readyWaitGroup = &sync.WaitGroup{}
	l.readyWaitGroup.Add(1)
	go func() {
		outBuffered := bufio.NewReader(out)
		line, _, err := outBuffered.ReadLine()
		if err != nil {
			t.Fatal(err)
		}
		expected := "tcpdump: listening on"
		if !strings.HasPrefix(string(line), expected) {
			t.Fatalf("expected buffer (%s) to be (%s)", string(line), string(expected))
		}
		l.readyWaitGroup.Done()

		io.Copy(f, outBuffered)
		f.Close()
		l.finishedWaitGroup.Done()
	}()
	return l
}

func TestBasic(t *testing.T) {
	topology := basicInit(t)
	err := topology.Compose.Start()
	require.Nil(t, err)
	defer topology.Compose.Clear()
	defer topology.Compose.Stop()

	err = topology.LANComputer.SudoExec("ip", "route", "del", "default").Run()
	require.Nil(t, err)
	ipAddress, err := topology.Router.GetIPAddressForNetwork(topology.LAN)
	require.Nil(t, err)
	cmd := topology.LANComputer.SudoExec("ip", "route", "add", "default", "via", ipAddress)
	stdoutPipe, err := cmd.StdoutPipe()
	require.Nil(t, err)
	err = cmd.Start()
	require.Nil(t, err)
	stdout, err := ioutil.ReadAll(stdoutPipe)
	require.Equal(t, string(stdout), "")
	err = cmd.Wait()
	require.Nil(t, err)

	type tcpdumpConfig struct {
		service  *dc.Service
		iface    string
		listener *tcpdumpListener
	}
	tcpdumps := []*tcpdumpConfig{
		&tcpdumpConfig{service: topology.LANComputer, iface: "eth0"},
		&tcpdumpConfig{service: topology.Router, iface: "eth0"},
		&tcpdumpConfig{service: topology.Router, iface: "eth1"},
		&tcpdumpConfig{service: topology.InternetComputer, iface: "eth0"},
	}
	for _, td := range tcpdumps {
		td.listener = tcpdump(t, td.service, td.iface)
		defer os.Remove(td.listener.path)
	}
	for _, td := range tcpdumps {
		td.listener.readyWaitGroup.Wait()
	}

	server := topology.InternetComputer.Exec("bash", "-c", "echo hello |nc -u -l 8000 -W 1")
	err = server.Start()
	require.Nil(t, err)
	defer func() {
		server.Kill()
	}()

	routerWANIPAddress, err := topology.Router.GetIPAddressForNetwork(topology.Internet)
	require.Nil(t, err)
	lanComputerIPAddress, err := topology.LANComputer.GetIPAddressForNetwork(topology.LAN)
	require.Nil(t, err)
	internetComputerIPAddress, err := topology.InternetComputer.GetIPAddressForNetwork(topology.Internet)
	require.Nil(t, err)
	cmd = topology.LANComputer.Exec("bash", "-c", fmt.Sprintf("echo ''| nc %s 8000 -p 12345 -u -W 1", internetComputerIPAddress))
	stdoutPipe, err = cmd.StdoutPipe()
	require.Nil(t, err)
	err = cmd.Start()
	require.Nil(t, err)
	stdout = []byte{}
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

	packets := btree.New(4)
	for _, td := range tcpdumps {
		td.listener.cmd.Signal(syscall.SIGINT)
		td.listener.cmd.Wait()
		td.listener.finishedWaitGroup.Wait()
		handle, err := pcap.OpenOffline(td.listener.path)
		if err != nil {
			t.Errorf("error reading pcap in %s (%s): %s", td.service.ContainerName, td.iface, err.Error())
			continue
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packets.ReplaceOrInsert(&tests.PacketItem{
				Packet:    packet,
				Service:   td.service.ContainerName,
				Interface: td.iface,
			})
		}
	}

	type step struct {
		service string
		srcIP   net.IP
		srcPort int
		dstIP   net.IP
		dstPort int
		payload []byte
	}
	currentStepIndex := 0
	steps := []step{
		step{service: "lancomputer", srcIP: net.ParseIP(lanComputerIPAddress), srcPort: 12345, dstIP: net.ParseIP(internetComputerIPAddress), dstPort: 8000, payload: []byte("\n")},
		step{service: "router", srcIP: net.ParseIP(lanComputerIPAddress), srcPort: 12345, dstIP: net.ParseIP(internetComputerIPAddress), dstPort: 8000, payload: []byte("\n")},
		step{service: "router", srcIP: net.ParseIP(routerWANIPAddress), srcPort: 12345, dstIP: net.ParseIP(internetComputerIPAddress), dstPort: 8000, payload: []byte("\n")},
		step{service: "internetcomputer", srcIP: net.ParseIP(routerWANIPAddress), srcPort: 12345, dstIP: net.ParseIP(internetComputerIPAddress), dstPort: 8000, payload: []byte("\n")},
		step{service: "internetcomputer", dstIP: net.ParseIP(routerWANIPAddress), dstPort: 12345, srcIP: net.ParseIP(internetComputerIPAddress), srcPort: 8000, payload: []byte("hello\n")},
		step{service: "router", dstIP: net.ParseIP(routerWANIPAddress), dstPort: 12345, srcIP: net.ParseIP(internetComputerIPAddress), srcPort: 8000, payload: []byte("hello\n")},
		step{service: "lancomputer", dstIP: net.ParseIP(lanComputerIPAddress), dstPort: 12345, srcIP: net.ParseIP(internetComputerIPAddress), srcPort: 8000, payload: []byte("hello\n")},
	}
	packets.Ascend(func(i btree.Item) bool {
		if currentStepIndex >= len(steps) {
			return false
		}
		pi := i.(*tests.PacketItem)
		step := steps[currentStepIndex]
		if pi.Service == step.service && pi.IPv4SrcIP().String() == step.srcIP.String() && pi.UDPSrcPort() == step.srcPort && pi.IPv4DstIP().String() == step.dstIP.String() && pi.UDPDstPort() == step.dstPort {
			currentStepIndex += 1
        }
		return true
	})

	if currentStepIndex < len(steps) {
		t.Errorf("missing step %d: %#v", currentStepIndex, steps[currentStepIndex])
	}
	if t.Failed() {
		logs, _ := topology.Compose.Logs()
		print(logs)

		packets.Ascend(func(i btree.Item) bool {
			pi := i.(*tests.PacketItem)
			fmt.Printf("s=%s i=%s p=(%s)\n", pi.Service, pi.Interface, pi.Packet.String())
			return true
		})
	}
}
