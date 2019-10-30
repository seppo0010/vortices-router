# Vortices Router

Vortices Router is a simple and configurable NAT. It is not meant to be used in
production but to be used inside a Docker container with iptables to test
different environments.

## Setup

```
$ sudo apt install -y libpcap0.8-dev libnetfilter-queue-dev docker-compose
$ go test ./... -v
$ pushd tests && go test ./... -v -p 1 && popd
```
