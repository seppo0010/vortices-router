package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostsComplete(t *testing.T) {
	ips, stop := Hosts("192.168.0.1/30")
	defer func() { stop <- nil }()
	receivedIPs := []string{}
	for ip := range ips {
		receivedIPs = append(receivedIPs, ip)
	}
	assert.Equal(t, receivedIPs, []string{"192.168.0.1", "192.168.0.2", "192.168.0.3"})
}

func TestHostsBreak(t *testing.T) {
	ips, stop := Hosts("192.168.0.1/30")
	receivedIPs := []string{}
	for ip := range ips {
		receivedIPs = append(receivedIPs, ip)

		stop <- nil
	}
	assert.Equal(t, receivedIPs, []string{"192.168.0.1"})
}
