# Vortices Router

Vortices Router is a simple and configurable NAT. It is not meant to be used in
production but to be used inside a Docker container with iptables to test
different environments.

## Setup

This instructions are just inspirational at this moment, like DDD
(Documentation Driven Development)

```
$ go build .
$ sudo setcap 'cap_net_admin=+ep' vortices-router
$ sudo iptables -A FORWARD -i eth0 -o eth1 -j NFQUEUE --queue-num 1
$ sudo iptables -A FORWARD -i eth1 -o eth0 -j NFQUEUE --queue-num 2
$ sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
$ sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
$ sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
$ ./vortices-router --wan-interface eth0 --wan-queue 1 --lan-interface eth1 --lan-queue 2
```
