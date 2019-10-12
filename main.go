package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

var usageError error
var errNoWANInterface = errors.New("at least one WAN interface must be provided")
var errNoLANInterface = errors.New("at least one LAN interface must be provided")
var errNoWANQueue = errors.New("at least one WAN queue must be provided")
var errNoLANQueue = errors.New("at least one LAN queue must be provided")
var lanInterfaceAndQueueMistmachFormat = "the same number of LAN interfaces and queues must be provided, got %d and %d"
var wanInterfaceAndQueueMistmachFormat = "the same number of WAN interfaces and queues must be provided, got %d and %d"
var errMixedAlias = errors.New("WAN and LAN alias must both or neither be provided")
var aliasNotFoundFormat = "alias %s not found"

func init() {
	var usage bytes.Buffer
	flag.CommandLine.SetOutput(&usage)
	usage.Write([]byte("Usage of %s:\n"))
	flag.PrintDefaults()
	usageError = errors.New(string(usage.Bytes()))

	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
}

type addresses []net.HardwareAddr

func (as *addresses) String() string {
	vals := make([]string, len(*as))
	for i, a := range *as {
		vals[i] = a.String()
	}
	return strings.Join(vals, ",")
}

func (as *addresses) Set(value string) error {
	val, err := net.ParseMAC(value)
	if err != nil {
		return err
	}
	*as = append(*as, val)
	return nil
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

func findInterfaceForAlias(alias string) (*net.Interface, error) {
	addrs, err := net.LookupHost(alias)
	if err != nil {
		return nil, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ipToInterface := map[string]net.Interface{}
	for _, interface_ := range interfaces {
		addrs, err := interface_.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip := strings.Split(addr.String(), "/")[0]
			ipToInterface[ip] = interface_
		}
	}
	for _, addr := range addrs {
		if interface_, found := ipToInterface[addr]; found {
			return &interface_, nil
		}

	}
	return nil, fmt.Errorf(aliasNotFoundFormat, alias)
}

func setupForwardAndQueue(wanInterface, lanInterface string, lanQueue int) error {
	commands := [][]string{
		[]string{"iptables", "-A", "FORWARD", "-i", lanInterface, "-o", wanInterface, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(lanQueue)},
		[]string{"iptables", "-A", "FORWARD", "-i", wanInterface, "-o", lanInterface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		[]string{"iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wanInterface, "-j", "MASQUERADE"},
	}
	for _, command := range commands {
		if err := exec.Command(command[0], command[1:]...).Run(); err != nil {
			return err
		}
	}
	return nil
}

func getInterfacesAndQueues() (interfaces, queues, addresses, interfaces, error) {
	wanInterfaces := interfaces{}
	wanAlias := ""
	lanInterfaces := interfaces{}
	lanQueues := queues{}
	lanAddresses := addresses{}
	lanAlias := ""
	flag.StringVar(&wanAlias, "wan-alias", "", "WAN (wide area network) alias (e.g.: \"wan\"). Must be set along lan-alias.")
	flag.StringVar(&lanAlias, "lan-alias", "", "LAN (local area network) alias (e.g.: \"lan\"). Must be set along wan-alias.")
	flag.Var(&wanInterfaces, "wan-interface", "WAN (wide area network) interface (e.g.: \"eth0\"). Required if no alias is provided.")
	flag.Var(&lanInterfaces, "lan-interface", "LAN (local area network) interface (e.g.: \"eth1\"). Required if no alias is provided.")
	flag.Var(&lanQueues, "lan-queue", "LAN (local area network) nf queue (e.g.: \"2\"). Required if no alias is provided.")
	flag.Var(&lanAddresses, "lan-mac-address", "LAN (local area network) mac address (e.g.: \"5e:73:2a:c4:53:81\"). Required if no alias is provided.")

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		return nil, nil, nil, nil, usageError
	}
	flag.Parse()

	if (wanAlias == "" && lanAlias != "") || (wanAlias != "" && lanAlias == "") {
		return nil, nil, nil, nil, errMixedAlias
	}

	if wanAlias != "" && lanAlias != "" {
		wanInterface, err := findInterfaceForAlias(wanAlias)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		lanInterface, err := findInterfaceForAlias(lanAlias)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// 34 was randomly selected
		// well, not really randomly, but randomly enough
		lanQueue := 34
		err = setupForwardAndQueue(wanInterface.Name, lanInterface.Name, lanQueue)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		wanInterfaces = append(wanInterfaces, wanInterface.Name)
		lanInterfaces = append(lanInterfaces, lanInterface.Name)
		lanAddresses = append(lanAddresses, lanInterface.HardwareAddr)
		lanQueues = append(lanQueues, lanQueue)
	}

	if len(wanInterfaces) == 0 {
		return nil, nil, nil, nil, errNoWANInterface
	}
	if len(lanInterfaces) == 0 {
		return nil, nil, nil, nil, errNoLANInterface
	}
	if len(lanQueues) == 0 {
		return nil, nil, nil, nil, errNoLANQueue
	}
	if len(lanInterfaces) != len(lanQueues) {
		return nil, nil, nil, nil, fmt.Errorf(lanInterfaceAndQueueMistmachFormat, len(lanInterfaces), len(lanQueues))
	}
	return lanInterfaces, lanQueues, lanAddresses, wanInterfaces, nil
}

func main() {
	lanInterfaces, lanQueues, lanAddresses, wanInterfaces, err := getInterfacesAndQueues()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
	router, err := NewRouter(DefaultConfiguration(len(wanInterfaces)), lanInterfaces, lanQueues, lanAddresses, wanInterfaces)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
	router.Run()
}
