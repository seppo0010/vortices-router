package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var usageError error
var noWANInterface = errors.New("at least one WAN interface must be provided")
var noLANInterface = errors.New("at least one LAN interface must be provided")
var noWANQueue = errors.New("at least one WAN queue must be provided")
var noLANQueue = errors.New("at least one LAN queue must be provided")

func init() {
	var usage bytes.Buffer
	flag.CommandLine.SetOutput(&usage)
	usage.Write([]byte("Usage of %s:\n"))
	flag.PrintDefaults()
	usageError = errors.New(string(usage.Bytes()))
}

type interfaces []string

func (i *interfaces) String() string {
	return strings.Join(*i, ",")
}

func (i *interfaces) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type queues []int

func (i *queues) String() string {
	return strings.Trim(strings.Replace(fmt.Sprint(*i), " ", ",", -1), "[]")
}

func (i *queues) Set(value string) error {
	val, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	*i = append(*i, val)
	return nil
}

func getInterfacesAndQueues() (interfaces, queues, interfaces, queues, error) {
	wanInterfaces := interfaces{}
	wanQueues := queues{}
	lanInterfaces := interfaces{}
	lanQueues := queues{}
	flag.Var(&wanInterfaces, "wan-interface", "WAN (wide area network) interface (e.g.: eth0). At least 1 required.")
	flag.Var(&lanInterfaces, "lan-interface", "LAN (local area network) interface (e.g.: eth1). At least 1 required.")
	flag.Var(&wanQueues, "wan-queue", "WAN (wide area network) nf queue (e.g.: 1). At least 1 required.")
	flag.Var(&lanQueues, "lan-queue", "LAN (local area network) nf queue (e.g.: 2). At least 1 required.")

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		return nil, nil, nil, nil, usageError
	}
	flag.Parse()

	if len(wanInterfaces) == 0 {
		return nil, nil, nil, nil, noWANInterface
	}
	if len(lanInterfaces) == 0 {
		return nil, nil, nil, nil, noLANInterface
	}
	if len(wanQueues) == 0 {
		return nil, nil, nil, nil, noWANQueue
	}
	if len(lanQueues) == 0 {
		return nil, nil, nil, nil, noLANQueue
	}
	return lanInterfaces, lanQueues, wanInterfaces, wanQueues, nil
}

func main() {
	lanInterfaces, lanQueues, wanInterfaces, wanQueues, err := getInterfacesAndQueues()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
	router := NewRouter(DefaultConfiguration(), lanInterfaces, lanQueues, wanInterfaces, wanQueues)
	router.Run()
}