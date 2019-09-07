package main

import (
	"net"
	"os"
	"syscall"
	"time"
)

type UDPConn interface {
	Close() error
	File() (f *os.File, err error)
	LocalAddr() net.Addr
	Read(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadBuffer(bytes int) error
	SetReadDeadline(t time.Time) error
	SetWriteBuffer(bytes int) error
	SetWriteDeadline(t time.Time) error
	SyscallConn() (syscall.RawConn, error)
	Write(b []byte) (int, error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
	WriteTo(b []byte, addr net.Addr) (int, error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
}
