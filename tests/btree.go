package tests

import (
	"fmt"
	"time"

	"github.com/google/btree"
	"github.com/google/gopacket"
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
