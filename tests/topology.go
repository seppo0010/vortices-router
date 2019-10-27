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

func (service *Service) startEcho(cmd exec.Cmd) exec.Cmd {
	serverOut, _ := cmd.StdoutPipe()
	err := cmd.Start()
	require.Nil(service.T, err)
	serverOutBuffered := bufio.NewReader(serverOut)
	line, _, err := serverOutBuffered.ReadLine()
	expected := "Listening on"
	if !strings.HasPrefix(string(line), expected) {
		service.T.Fatalf("expected buffer (%s) to be (%s)", string(line), string(expected))
	}
	return cmd
}

func (service *Service) StartEchoServerGolang(message string, port, times int) exec.Cmd {
	return service.startEcho(service.Exec("bash", "-c",
		fmt.Sprintf(
			`echo 'package main; import "os"; import "net"; func main() { c, _ := net.ListenUDP("udp", &net.UDPAddr{Port:%d}); println("Listening on %d"); for i := 0; i < %d; i++ { buf := make([]byte, 1500); _, addr, _ := c.ReadFromUDP(buf); os.Stdout.Write(buf); c.WriteTo([]byte("%s\\n"), addr)}; }' > server.go; go run server.go`,
			port,
			port,
			times,
			message,
		),
	),
	)
}

func (service *Service) StartEchoServer(message string, port, times int) exec.Cmd {
	return service.startEcho(service.Exec("bash", "-c", fmt.Sprintf("echo %s |nc -u -l %d -W %d -v", message, port, times)))
}

func (service *Service) ReadEchoServer(remoteIP net.IP, remotePort, localPort, timeout int) []byte {
	cmd := service.Exec("bash", "-c", fmt.Sprintf("echo ''| nc %s %d -p %d -u -W 1 -w %d", remoteIP.String(), remotePort, localPort, timeout))
	stdoutPipe, err := cmd.StdoutPipe()
	require.Nil(service.T, err)
	err = cmd.Start()
	stdout, err := ioutil.ReadAll(stdoutPipe)
	cmd.Wait()
	require.Nil(service.T, err)
	return stdout
}

type TopologyConfiguration struct {
	NumberOfLANComputers uint
	RouterConfig         string
}

type Topology struct {
	LAN              *dc.Network
	Internet         *dc.Network
	Router           *Service
	LANComputer      *Service
	LANComputers     []*Service
	InternetComputer *Service
	Compose          *dc.Compose
	T                *testing.T
	TCPDumps         []*tcpdumpConfig
	packets          []*PacketItem
}

func NewTopology(t *testing.T, topologyConfig *TopologyConfiguration) *Topology {
	_, filename, _, _ := runtime.Caller(1)

	compose := dc.NewCompose(dc.ComposeConfig{})
	routerImage, err := compose.BuildDockerPath("router", path.Dir(path.Dir((path.Dir(filename)))))
	require.Nil(t, err)

	topology := &Topology{Compose: compose, T: t}
	topology.LAN = compose.AddNetwork("lan", dc.NetworkConfig{})
	topology.Internet = compose.AddNetwork("internet", dc.NetworkConfig{})
	routerConfig := ""
	if topologyConfig != nil {
		routerConfig = topologyConfig.RouterConfig
	}
	topology.Router = &Service{T: t, Service: compose.AddService("router", dc.ServiceConfig{
		Command:    []string{"./main", "--wan-alias", "wan", "--lan-alias", "lan", "--config", routerConfig},
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
	if topologyConfig != nil && topologyConfig.NumberOfLANComputers > 0 {
		topology.LANComputers = make([]*Service, topologyConfig.NumberOfLANComputers)
		for i, _ := range topology.LANComputers {
			topology.LANComputers[i] = &Service{T: t, Service: compose.AddService(fmt.Sprintf("lancomputer%d", i+1), computerConfig, []dc.ServiceNetworkConfig{
				dc.ServiceNetworkConfig{Network: topology.LAN},
			})}
		}
	}
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

func (s Step) String() string {
	return fmt.Sprintf("{service=%s, src=%s:%d, dst=%s:%d, payload=%v}", s.Service, s.SrcIP.String(), s.SrcPort, s.DstIP.String(), s.DstPort, s.Payload)
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
	if topology.LANComputers != nil {
		for _, c := range topology.LANComputers {
			topology.TCPDumps = append(topology.TCPDumps, &tcpdumpConfig{Service: c, Interface: "eth0"})
		}
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
		f, err := os.Stat(td.Listener.Path)
		if err != nil {
			topology.T.Errorf("error reading pcap in %s (%s): %s", td.Service.ContainerName, td.Interface, err.Error())
			continue
		}
		if f.Size() == 0 {
			topology.T.Logf("pcap is empty in %s (%s)", td.Service.ContainerName, td.Interface)
			continue
		}

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
	nextUsablePacket := 0
	for i, pi := range topology.Packets() {
		if currentStepIndex >= len(steps) {
			break
		}
		step := steps[currentStepIndex]
		if pi.Service == step.Service && pi.IPv4SrcIP().String() == step.SrcIP.String() && pi.UDPSrcPort() == step.SrcPort && pi.IPv4DstIP().String() == step.DstIP.String() && pi.UDPDstPort() == step.DstPort {
			currentStepIndex += 1
			nextUsablePacket = i + 1
		}
	}

	if currentStepIndex < len(steps) {
		topology.T.Errorf("missing step %d: %s", currentStepIndex, steps[currentStepIndex].String())
		for _, pi := range topology.Packets()[nextUsablePacket:] {
			topology.T.Logf("unread packet: %s", Step{Service: pi.Service, SrcIP: pi.IPv4SrcIP(), SrcPort: pi.UDPSrcPort(), DstIP: pi.IPv4DstIP(), DstPort: pi.UDPDstPort(), Payload: pi.UDPPayload()})
		}
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

func (topology *Topology) GetRouterWANIPAddress() net.IP {
	ip, err := topology.Router.GetIPAddressForNetwork(topology.Internet)
	require.Nil(topology.T, err)
	return net.ParseIP(ip)
}

func (topology *Topology) GetRouterLANIPAddress() net.IP {
	ip, err := topology.Router.GetIPAddressForNetwork(topology.LAN)
	require.Nil(topology.T, err)
	return net.ParseIP(ip)
}

func (topology *Topology) GetLANComputerIPAddress() net.IP {
	ip, err := topology.LANComputer.GetIPAddressForNetwork(topology.LAN)
	require.Nil(topology.T, err)
	return net.ParseIP(ip)
}

func (topology *Topology) GetInternetComputerIPAddress() net.IP {
	ip, err := topology.InternetComputer.GetIPAddressForNetwork(topology.Internet)
	require.Nil(topology.T, err)
	return net.ParseIP(ip)
}
