package tests

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

	"github.com/google/btree"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	dc "github.com/seppo0010/vortices-dockercompose"
	"github.com/seppo0010/vortices-dockercompose/exec"
	"github.com/stretchr/testify/require"
)

type Service struct {
	*dc.Service
	T *testing.T
}

func (service *Service) SetDefaultGateway(ip string) {
	err := service.SudoExec("ip", "route", "del", "default").Run()
	require.Nil(service.T, err)
	cmd := service.SudoExec("ip", "route", "add", "default", "via", ip)
	stdoutPipe, err := cmd.StdoutPipe()
	require.Nil(service.T, err)
	err = cmd.Start()
	require.Nil(service.T, err)
	stdout, err := ioutil.ReadAll(stdoutPipe)
	require.Equal(service.T, string(stdout), "")
	err = cmd.Wait()
	require.Nil(service.T, err)
}

type Topology struct {
	LAN              *dc.Network
	Internet         *dc.Network
	Router           *Service
	LANComputer      *Service
	InternetComputer *Service
	Compose          *dc.Compose
	T                *testing.T
	TCPDumps         []*tcpdumpConfig
	packets          []*PacketItem
}

func NewTopology(t *testing.T) *Topology {
	_, filename, _, _ := runtime.Caller(1)

	compose := dc.NewCompose(dc.ComposeConfig{})
	routerImage, err := compose.BuildDockerPath("router", path.Dir(path.Dir((path.Dir(filename)))))
	require.Nil(t, err)

	topology := &Topology{Compose: compose, T: t}
	topology.LAN = compose.AddNetwork("lan", dc.NetworkConfig{})
	topology.Internet = compose.AddNetwork("internet", dc.NetworkConfig{})
	topology.Router = &Service{T: t, Service: compose.AddService("router", dc.ServiceConfig{
		Command:    []string{"./main", "--wan-alias", "wan", "--lan-alias", "lan"},
		Image:      routerImage,
		Privileged: true,
	}, []dc.ServiceNetworkConfig{
		dc.ServiceNetworkConfig{Network: topology.LAN, Aliases: []string{"lan"}},
		dc.ServiceNetworkConfig{Network: topology.Internet, Aliases: []string{"wan"}},
	})}
	computerImage, err := compose.BuildDocker("computer", `
FROM ubuntu
RUN apt update && apt install -y iproute2 netcat-openbsd iputils-ping tcpdump
    `)
	require.Nil(t, err)
	computerConfig := dc.ServiceConfig{Image: computerImage, Command: []string{"sleep", "infinity"}}
	topology.LANComputer = &Service{T: t, Service: compose.AddService("lancomputer", computerConfig, []dc.ServiceNetworkConfig{
		dc.ServiceNetworkConfig{Network: topology.LAN},
	})}
	topology.InternetComputer = &Service{T: t, Service: compose.AddService("internetcomputer", computerConfig, []dc.ServiceNetworkConfig{
		dc.ServiceNetworkConfig{Network: topology.Internet},
	})}
	return topology
}

type tcpdumpListener struct {
	Cmd               exec.Cmd
	Path              string
	FinishedWaitGroup *sync.WaitGroup
	ReadyWaitGroup    *sync.WaitGroup
}

type tcpdumpConfig struct {
	Service   *Service
	Interface string
	Listener  *tcpdumpListener
}

type Step struct {
	Service string
	SrcIP   net.IP
	SrcPort int
	DstIP   net.IP
	DstPort int
	Payload []byte
}

func tcpdump(t *testing.T, service *Service, iface string) *tcpdumpListener {
	l := &tcpdumpListener{}
	l.Cmd = service.Exec("tcpdump", "-i", iface, "-l", "--immediate-mode", "-w", "-", "udp")
	out, _ := l.Cmd.StdoutPipe()
	_, _ = l.Cmd.StderrPipe()
	l.Cmd.Start()
	f, _ := ioutil.TempFile("", fmt.Sprintf("%s*.pcap", service.ContainerName))
	l.Path = f.Name()
	l.FinishedWaitGroup = &sync.WaitGroup{}
	l.FinishedWaitGroup.Add(1)
	l.ReadyWaitGroup = &sync.WaitGroup{}
	l.ReadyWaitGroup.Add(1)
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
		l.ReadyWaitGroup.Done()

		io.Copy(f, outBuffered)
		f.Close()
		l.FinishedWaitGroup.Done()
	}()
	return l
}

func (topology *Topology) StartTCPDump() {
	topology.TCPDumps = []*tcpdumpConfig{
		&tcpdumpConfig{Service: topology.LANComputer, Interface: "eth0"},
		&tcpdumpConfig{Service: topology.Router, Interface: "eth0"},
		&tcpdumpConfig{Service: topology.Router, Interface: "eth1"},
		&tcpdumpConfig{Service: topology.InternetComputer, Interface: "eth0"},
	}
	for _, td := range topology.TCPDumps {
		td.Listener = tcpdump(topology.T, td.Service, td.Interface)
	}
	for _, td := range topology.TCPDumps {
		td.Listener.ReadyWaitGroup.Wait()
	}
}

func (topology *Topology) Packets() []*PacketItem {
	if topology.packets != nil {
		return topology.packets
	}
	packets := btree.New(4)
	for _, td := range topology.TCPDumps {
		defer os.Remove(td.Listener.Path)
		td.Listener.Cmd.Signal(syscall.SIGINT)
		td.Listener.Cmd.Wait()
		td.Listener.FinishedWaitGroup.Wait()
		handle, err := pcap.OpenOffline(td.Listener.Path)
		if err != nil {
			topology.T.Errorf("error reading pcap in %s (%s): %s", td.Service.ContainerName, td.Interface, err.Error())
			continue
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packets.ReplaceOrInsert(&PacketItem{
				Packet:    packet,
				Service:   td.Service.ContainerName,
				Interface: td.Interface,
			})
		}
	}

	packetList := make([]*PacketItem, 0, packets.Len())
	packets.Ascend(func(i btree.Item) bool {
		pi := i.(*PacketItem)
		packetList = append(packetList, pi)
		return true
	})
	topology.packets = packetList
	return packetList
}

func (topology *Topology) ValidateSteps(steps []Step) {
	currentStepIndex := 0
	for _, pi := range topology.Packets() {
		if currentStepIndex >= len(steps) {
			break
		}
		step := steps[currentStepIndex]
		if pi.Service == step.Service && pi.IPv4SrcIP().String() == step.SrcIP.String() && pi.UDPSrcPort() == step.SrcPort && pi.IPv4DstIP().String() == step.DstIP.String() && pi.UDPDstPort() == step.DstPort {
			currentStepIndex += 1
		}
	}

	if currentStepIndex < len(steps) {
		topology.T.Errorf("missing step %d: %#v", currentStepIndex, steps[currentStepIndex])
	}
}

func (topology *Topology) PrintDebugIfFailed() {
	if topology.T.Failed() {
		topology.PrintDebug()
	}
}
func (topology *Topology) PrintDebug() {
	logs, _ := topology.Compose.Logs()
	print(logs)

	for _, pi := range topology.Packets() {
		fmt.Printf("s=%s i=%s p=(%s)\n", pi.Service, pi.Interface, pi.Packet.String())
	}
}
