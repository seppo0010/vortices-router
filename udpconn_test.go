package main

import (
	"net"
	"os"
	"syscall"
	"time"
)

type UDPConnMock struct {
	network string
	laddr   *net.UDPAddr
}

func (u *UDPConnMock) Close() error                                    { return nil }
func (u *UDPConnMock) File() (f *os.File, err error)                   { return nil, nil }
func (u *UDPConnMock) LocalAddr() net.Addr                             { return u.laddr }
func (u *UDPConnMock) Read(b []byte) (int, error)                      { return 0, nil }
func (u *UDPConnMock) ReadFrom(b []byte) (int, net.Addr, error)        { return 0, nil, nil }
func (u *UDPConnMock) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) { return 0, nil, nil }
func (u *UDPConnMock) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return 0, 0, 0, nil, nil
}
func (u *UDPConnMock) RemoteAddr() net.Addr                  { return nil }
func (u *UDPConnMock) SetDeadline(t time.Time) error         { return nil }
func (u *UDPConnMock) SetReadBuffer(bytes int) error         { return nil }
func (u *UDPConnMock) SetReadDeadline(t time.Time) error     { return nil }
func (u *UDPConnMock) SetWriteBuffer(bytes int) error        { return nil }
func (u *UDPConnMock) SetWriteDeadline(t time.Time) error    { return nil }
func (u *UDPConnMock) SyscallConn() (syscall.RawConn, error) { return nil, nil }
func (u *UDPConnMock) Write(b []byte) (int, error)           { return 0, nil }
func (u *UDPConnMock) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return 0, 0, nil
}
func (u *UDPConnMock) WriteTo(b []byte, addr net.Addr) (int, error)        { return 0, nil }
func (u *UDPConnMock) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) { return 0, nil }
