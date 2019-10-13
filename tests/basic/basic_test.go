package basic

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"runtime"
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
	"github.com/stretchr/testify/assert"
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

func tcpdump(service *dc.Service, iface string) (exec.Cmd, string, *sync.WaitGroup) {
	cmd := service.Exec("bash", "-c", fmt.Sprintf("tcpdump -i %s -n -l -w - udp 2> /dev/null", iface))
	out, _ := cmd.StdoutPipe()
	cmd.Start()
	f, _ := ioutil.TempFile("", fmt.Sprintf("%s*.pcap", service.ContainerName))
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		io.Copy(f, out)
		f.Close()
		wg.Done()
	}()
	return cmd, f.Name(), wg
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
		service *dc.Service
		iface   string
		path    string
		cmd     exec.Cmd
		wg      *sync.WaitGroup
	}
	tcpdumps := []*tcpdumpConfig{
		&tcpdumpConfig{service: topology.LANComputer, iface: "eth0"},
		&tcpdumpConfig{service: topology.Router, iface: "eth0"},
		&tcpdumpConfig{service: topology.Router, iface: "eth1"},
		&tcpdumpConfig{service: topology.InternetComputer, iface: "eth0"},
	}
	for _, td := range tcpdumps {
		td.cmd, td.path, td.wg = tcpdump(td.service, td.iface)
		defer os.Remove(td.path)
	}

	server := topology.InternetComputer.Exec("bash", "-c", "echo hello |nc -u -l 8000 -W 1")
	err = server.Start()
	require.Nil(t, err)
	defer func() {
		server.Kill()
	}()

	require.Nil(t, err)
	internetComputerIPAddress, err := topology.InternetComputer.GetIPAddressForNetwork(topology.Internet)
	require.Nil(t, err)
	cmd = topology.LANComputer.Exec("bash", "-c", fmt.Sprintf("echo ''| nc %s 8000 -u -W 1", internetComputerIPAddress))
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
		logs, _ := topology.Compose.Logs()
		print(logs)
		t.Error("timed out")
	case <-done:
	}

	logs, _ := topology.Compose.Logs()
	print(logs)

	packets := btree.New(4)
	for _, td := range tcpdumps {
		td.cmd.Signal(syscall.SIGINT)
		td.cmd.Wait()
		td.wg.Wait()
		handle, err := pcap.OpenOffline(td.path)
		if err != nil {
			assert.Nil(t, err)
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

	packets.Ascend(func(i btree.Item) bool {
		pi := i.(*tests.PacketItem)
		fmt.Printf("s=%s i=%s p=(%s)\n", pi.Service, pi.Interface, pi.Packet.String())
		return true
	})

	require.Nil(t, err)
	require.Equal(t, string(stdout), "hello\n")
}
