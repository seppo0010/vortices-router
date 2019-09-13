package main

import (
	"net"
	"os"
	"syscall"
	"time"
)

type UDPConnPacket struct {
	data  []byte
	oob   []byte
	flags int
	addr  *net.UDPAddr
	err   error
}

type UDPConnMock struct {
	network string
	laddr   *net.UDPAddr

	written      map[string][][]byte
	toRead       []*UDPConnPacket
	readDeadline time.Time
}

func (u *UDPConnMock) Close() error                  { return nil }
func (u *UDPConnMock) File() (f *os.File, err error) { return nil, nil }
func (u *UDPConnMock) LocalAddr() net.Addr           { return u.laddr }

func (u *UDPConnMock) Read(b []byte) (int, error) {
	n, _, err := u.ReadFromUDP(b)
	return n, err
}

func (u *UDPConnMock) ReadFrom(b []byte) (int, net.Addr, error) {
	return u.ReadFromUDP(b)
}

func (u *UDPConnMock) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, _, _, addr, err := u.ReadMsgUDP(b, nil)
	return n, addr, err
}

func (u *UDPConnMock) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if u.toRead == nil || len(u.toRead) == 0 {
		return 0, 0, 0, nil, newTimeout()
	}
	packet := u.toRead[0]
	u.toRead = u.toRead[1:]
	for i := 0; i < len(packet.data); i++ {
		b[i] = packet.data[i]
	}
	if packet.oob != nil {
		for i := 0; i < len(packet.oob); i++ {
			oob[i] = packet.oob[i]
		}
	}
	return len(packet.data), len(packet.oob), packet.flags, packet.addr, packet.err
}
func (u *UDPConnMock) RemoteAddr() net.Addr          { return nil }
func (u *UDPConnMock) SetDeadline(t time.Time) error { return nil }
func (u *UDPConnMock) SetReadBuffer(bytes int) error { return nil }

func (u *UDPConnMock) SetReadDeadline(t time.Time) error {
	u.readDeadline = t
	return nil
}

func (u *UDPConnMock) SetWriteBuffer(bytes int) error        { return nil }
func (u *UDPConnMock) SetWriteDeadline(t time.Time) error    { return nil }
func (u *UDPConnMock) SyscallConn() (syscall.RawConn, error) { return nil, nil }
func (u *UDPConnMock) Write(b []byte) (int, error)           { return 0, nil }
func (u *UDPConnMock) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return 0, 0, nil
}
func (u *UDPConnMock) WriteTo(b []byte, addr net.Addr) (int, error) { return 0, nil }

func (u *UDPConnMock) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if u.written == nil {
		u.written = map[string][][]byte{}
	}
	endpoint := addr.String()
	if _, found := u.written[endpoint]; !found {
		u.written[endpoint] = make([][]byte, 0, 1)
	}
	u.written[endpoint] = append(u.written[endpoint], b)
	return len(b), nil
}

type timeoutError struct{}

func (timeoutError) Error() string {
	return "i/o timeout"
}

func (timeoutError) Timeout() bool {
	return true
}

func (timeoutError) Temporary() bool {
	return false
}

func newTimeout() timeoutError {
	return timeoutError{}
}
