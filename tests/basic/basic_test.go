package basic

import (
	"path"
	"runtime"
	"testing"

	dc "github.com/seppo0010/vortices-dockercompose"
	"github.com/stretchr/testify/assert"
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
	assert.Nil(t, err)

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
	computerConfig := dc.ServiceConfig{Image: "ubuntu", Command: []string{"sleep", "infinity"}}
	topology.LANComputer = compose.AddService("lancomputer", computerConfig, []dc.ServiceNetworkConfig{
		dc.ServiceNetworkConfig{Network: topology.LAN},
	})
	topology.InternetComputer = compose.AddService("internetcomputer", computerConfig, []dc.ServiceNetworkConfig{
		dc.ServiceNetworkConfig{Network: topology.Internet},
	})
	return topology
}

func TestBasic(t *testing.T) {
	topology := basicInit(t)
	err := topology.Compose.Start()
	assert.Nil(t, err)
	err = topology.Compose.Stop()
	assert.Nil(t, err)
}
