package main

import (
	"net"
	"testing"
)

func TestIPAddressPoolingPaired(t *testing.T) {
	numIPAddresses := 3
	pool := NewIPAddressPoolingPaired(numIPAddresses)
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.0.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
		net.ParseIP("127.0.0.2"),
	}
	lastIP := net.ParseIP("127.0.0.3")

	// new IPs should round robin
	for i, ip := range ips {
		index := pool.GetIndexForIP(ip)
		if index != i%numIPAddresses {
			t.Errorf("expected index %d for ip %s, got %d", i, ip.String(), index)
		}
	}

	// existing IPs should maintain their index
	for i, ip := range ips {
		index := pool.GetIndexForIP(ip)
		if index != i%numIPAddresses {
			t.Errorf("expected index %d for ip %s, got %d", i, ip.String(), index)
		}
	}

	// trying a new one just in case reads messed it up
	index := pool.GetIndexForIP(lastIP)
	if index != len(ips)%numIPAddresses {
		t.Errorf("expected index %d for ip %s, got %d", len(ips), lastIP.String(), index)
	}
}

func TestGetExternalPortForInternalPort_Preservation(t *testing.T) {
	c := Configuration{PortAssignment: []PortAssignment{PortAssignmentPreservation}}
	port := 80
	candidates, _ := c.GetExternalPortForInternalPort(port)
	collectedCandidates := []PortCandidate{}
	for candidate := range candidates {
		collectedCandidates = append(collectedCandidates, candidate)
	}
	if len(collectedCandidates) != 1 {
		t.Fatalf("expected one collected candidate, got %d", len(collectedCandidates))
	}

	if collectedCandidates[0].Port != port {
		t.Fatalf("expected collected candidate's port to be %d, got %d", port, collectedCandidates[0].Port)
	}

	if collectedCandidates[0].Force == true {
		t.Fatalf("expected collected candidate force to be false, got true")
	}
}

func TestGetExternalPortForInternalPort_PreservationOverloading(t *testing.T) {
	c := Configuration{PortAssignment: []PortAssignment{PortAssignmentPreservation, PortAssignmentPreservationOverloading}}
	port := 80
	candidates, _ := c.GetExternalPortForInternalPort(port)
	collectedCandidates := []PortCandidate{}
	for candidate := range candidates {
		collectedCandidates = append(collectedCandidates, candidate)
	}
	if len(collectedCandidates) != 2 {
		t.Fatalf("expected one collected candidate, got %d", len(collectedCandidates))
	}

	if collectedCandidates[0].Port != port {
		t.Fatalf("expected first collected candidate's port to be %d, got %d", port, collectedCandidates[0].Port)
	}
	if collectedCandidates[0].Force == true {
		t.Fatalf("expected first collected candidate force to be false, got true")
	}

	if collectedCandidates[1].Port != port {
		t.Fatalf("expected second collected candidate's port to be %d, got %d", port, collectedCandidates[0].Port)
	}
	if collectedCandidates[1].Force == false {
		t.Fatalf("expected second collected candidate force to be true, got false")
	}
}

func TestGetExternalPortForInternalPort_RangePreservation(t *testing.T) {
	c := Configuration{PortAssignment: []PortAssignment{PortAssignmentRangePreservation}}
	port := 80
	candidates, _ := c.GetExternalPortForInternalPort(port)
	expectedCandidates := map[int]bool{}
	for i := 1; i < 1024; i++ {
		expectedCandidates[i] = true
	}
	for candidate := range candidates {
		if val, _ := expectedCandidates[candidate.Port]; !val {
			t.Fatalf("received unexpected port %d either twice or once completely unexpected", candidate.Port)
		}
		if candidate.Force {
			t.Fatalf("received unexpected force candidate for port %d", candidate.Port)
		}
		delete(expectedCandidates, candidate.Port)
	}
	if len(expectedCandidates) > 0 {
		t.Errorf("some expected ports were not received: %#v", expectedCandidates)
	}
}

func TestGetExternalPortForInternalPort_RangePreservation2(t *testing.T) {
	c := Configuration{PortAssignment: []PortAssignment{PortAssignmentRangePreservation}}
	port := 10266
	candidates, _ := c.GetExternalPortForInternalPort(port)
	expectedCandidates := map[int]bool{}
	for i := 1024; i <= 65535; i++ {
		expectedCandidates[i] = true
	}
	for candidate := range candidates {
		if val, _ := expectedCandidates[candidate.Port]; !val {
			t.Fatalf("received unexpected port %d either twice or once completely unexpected", candidate.Port)
		}
		if candidate.Force {
			t.Fatalf("received unexpected force candidate for port %d", candidate.Port)
		}
		delete(expectedCandidates, candidate.Port)
	}
	if len(expectedCandidates) > 0 {
		t.Errorf("some expected ports were not received: %#v", expectedCandidates)
	}
}

func TestGetExternalPortForInternalPort_NoRangePreservation(t *testing.T) {
	c := Configuration{PortAssignment: []PortAssignment{PortAssignmentNoPreservation}}
	port := 10266
	candidates, _ := c.GetExternalPortForInternalPort(port)
	expectedCandidates := map[int]bool{}
	for i := 1; i <= 65535; i++ {
		expectedCandidates[i] = true
	}
	for candidate := range candidates {
		if val, _ := expectedCandidates[candidate.Port]; !val {
			t.Fatalf("received unexpected port %d either twice or once completely unexpected", candidate.Port)
		}
		if candidate.Force {
			t.Fatalf("received unexpected force candidate for port %d", candidate.Port)
		}
		delete(expectedCandidates, candidate.Port)
	}
	if len(expectedCandidates) > 0 {
		t.Errorf("some expected ports were not received: %#v", expectedCandidates)
	}
}

func TestGetExternalPortForInternalPort_RangePreservation_then_NoRangePreservation(t *testing.T) {
	c := Configuration{PortAssignment: []PortAssignment{PortAssignmentRangePreservation, PortAssignmentNoPreservation}}
	port := 10266
	candidates, _ := c.GetExternalPortForInternalPort(port)
	expectedCandidates := map[int]bool{}
	for i := 1024; i <= 65535; i++ {
		expectedCandidates[i] = true
	}
	for candidate := range candidates {
		if val, _ := expectedCandidates[candidate.Port]; !val {
			t.Fatalf("received unexpected port %d either twice or once completely unexpected", candidate.Port)
		}
		if candidate.Force {
			t.Fatalf("received unexpected force candidate for port %d", candidate.Port)
		}
		delete(expectedCandidates, candidate.Port)
		if candidate.Port >= 1024 && len(expectedCandidates) == 0 {
			for i := 1; i <= 1023; i++ {
				expectedCandidates[i] = true
			}
		}
	}
	if len(expectedCandidates) > 0 {
		t.Errorf("some expected ports were not received: %#v", expectedCandidates)
	}
}

func TestGetExternalPortForInternalPort_Stop(t *testing.T) {
	c := Configuration{PortAssignment: []PortAssignment{PortAssignmentRangePreservation, PortAssignmentNoPreservation}}
	candidates, stop := c.GetExternalPortForInternalPort(1)
	attempts := 0
	for _ = range candidates {
		attempts++
		stop()
	}
	if attempts > 1 {
		t.Errorf("expected exactly one attempt, got %d", attempts)
	}
}
