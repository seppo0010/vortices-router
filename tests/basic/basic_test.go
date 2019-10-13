package basic

import (
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"runtime"
	"syscall"
	"testing"
	"time"

	dc "github.com/seppo0010/vortices-dockercompose"
	"github.com/seppo0010/vortices-dockercompose/exec"
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

func tcpdump(service *dc.Service, iface string) (exec.Cmd, io.ReadCloser) {
	cmd := service.Exec("tcpdump", "-i", iface, "-n", "-l")
	out, _ := cmd.StdoutPipe()
	cmd.Start()
	return cmd, out
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
		out     io.ReadCloser
		cmd     exec.Cmd
	}
	tcpdumps := []*tcpdumpConfig{
		&tcpdumpConfig{topology.LANComputer, "eth0", nil, nil},
		&tcpdumpConfig{topology.Router, "eth0", nil, nil},
		&tcpdumpConfig{topology.Router, "eth1", nil, nil},
		&tcpdumpConfig{topology.InternetComputer, "eth0", nil, nil},
	}
	for _, td := range tcpdumps {
		td.cmd, td.out = tcpdump(td.service, td.iface)
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
		t.Fatal("timed out")
	case <-done:
	}

	logs, _ := topology.Compose.Logs()
	print(logs)

	for _, td := range tcpdumps {
		td.cmd.Signal(syscall.SIGINT)
		s, _ := ioutil.ReadAll(td.out)
		fmt.Printf("service %s, interface %s:\n%s\n", td.service.ContainerName, td.iface, string(s))
	}

	require.Nil(t, err)
	require.Equal(t, string(stdout), "hello\n")
}
