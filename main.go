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
var errNoWANInterface = errors.New("at least one WAN interface must be provided")
var errNoLANInterface = errors.New("at least one LAN interface must be provided")
var errNoWANQueue = errors.New("at least one WAN queue must be provided")
var errNoLANQueue = errors.New("at least one LAN queue must be provided")
var lanInterfaceAndQueueMistmachFormat = "the same number of LAN interfaces and queues must be provided, got %d and %d"
var wanInterfaceAndQueueMistmachFormat = "the same number of WAN interfaces and queues must be provided, got %d and %d"

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
		return nil, nil, nil, nil, errNoWANInterface
	}
	if len(lanInterfaces) == 0 {
		return nil, nil, nil, nil, errNoLANInterface
	}
	if len(wanQueues) == 0 {
		return nil, nil, nil, nil, errNoWANQueue
	}
	if len(lanQueues) == 0 {
		return nil, nil, nil, nil, errNoLANQueue
	}
	if len(lanInterfaces) != len(lanQueues) {
		return nil, nil, nil, nil, fmt.Errorf(lanInterfaceAndQueueMistmachFormat, len(lanInterfaces), len(lanQueues))
	}
	if len(wanInterfaces) != len(wanQueues) {
		return nil, nil, nil, nil, fmt.Errorf(wanInterfaceAndQueueMistmachFormat, len(wanInterfaces), len(wanQueues))
	}
	return lanInterfaces, lanQueues, wanInterfaces, wanQueues, nil
}

func main() {
	lanInterfaces, lanQueues, wanInterfaces, wanQueues, err := getInterfacesAndQueues()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
	router, err := NewRouter(DefaultConfiguration(len(wanInterfaces)), lanInterfaces, lanQueues, wanInterfaces, wanQueues)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
	router.Run()
}
