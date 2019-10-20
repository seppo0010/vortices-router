package tests

import (
	"fmt"
	"net"
	"time"

	"github.com/google/btree"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketItem struct {
	gopacket.Packet
	Service   string
	Interface string
}

func (pi *PacketItem) Less(than btree.Item) bool {
	if pi2, ok := than.(*PacketItem); ok {
		return pi.Metadata().CaptureInfo.Timestamp.Before(pi2.Metadata().CaptureInfo.Timestamp)
	}
	if date, ok := than.(*TimeItem); ok {
		return pi.Metadata().CaptureInfo.Timestamp.Before(date.Time)
	}
	panic(fmt.Sprintf("unsupported btree item: %T", than))
}

func (pi *PacketItem) UDPSrcPort() int {
	if udpLayer := pi.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return int(udp.SrcPort)
	}
	return -1
}

func (pi *PacketItem) UDPDstPort() int {
	if udpLayer := pi.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return int(udp.DstPort)
	}
	return -1
}

func (pi *PacketItem) IPv4SrcIP() net.IP {
	if ipv4Layer := pi.Packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		return ipv4.SrcIP
	}
	return net.IP{}
}

func (pi *PacketItem) IPv4DstIP() net.IP {
	if ipv4Layer := pi.Packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		return ipv4.DstIP
	}
	return net.IP{}
}

type TimeItem struct {
	time.Time
}

func (ti *TimeItem) Less(than btree.Item) bool {
	if pi2, ok := than.(*PacketItem); ok {
		return ti.Before(pi2.Metadata().CaptureInfo.Timestamp)
	}
	if date, ok := than.(*TimeItem); ok {
		return ti.Before(date.Time)
	}
	panic(fmt.Sprintf("unsupported btree item: %T", than))
}
