package main

import (
	"bytes"
	"encoding/json"
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
var aliasNotFoundFormat = "alias %s not found"
var errExtraIPAddressNoHostFound = errors.New("Could not find an extra IP address in the network")

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

type aliases []string

func (i *aliases) String() string {
	return strings.Join(*i, ",")
}

func (i *aliases) Set(value string) error {
	*i = append(*i, value)
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

func findInterfacesForAliases(aliases []string) ([]*net.Interface, error) {
	ifaces := make([]*net.Interface, len(aliases))
	for i, alias := range aliases {
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
		ifaces[i] = nil
		for _, addr := range addrs {
			if interface_, found := ipToInterface[addr]; found {
				ifaces[i] = &interface_
				break
			}
		}
		if ifaces[i] == nil {
			return nil, fmt.Errorf(aliasNotFoundFormat, alias)
		}
	}
	return ifaces, nil
}

func setupForwardAndQueue(wanInterface, lanInterface string, lanQueue int) error {
	commands := [][]string{
		[]string{"iptables", "-A", "FORWARD", "-i", lanInterface, "-o", wanInterface, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(lanQueue)},
		[]string{"iptables", "-A", "FORWARD", "-p", "udp", "!", "-i", wanInterface, "-o", lanInterface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		[]string{"iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "udp", "!", "-o", wanInterface, "-j", "MASQUERADE"},
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
	wanAliases := aliases{}
	lanInterfaces := interfaces{}
	lanQueues := queues{}
	lanAddresses := addresses{}
	lanAliases := aliases{}
	extraIPAddresses := 0
	extraIPAddressesWANAlias := ""
	flag.Var(&wanAliases, "wan-alias", "WAN (wide area network) aliases (e.g.: \"wan\"). Must be set along lan-alias.")
	flag.Var(&lanAliases, "lan-alias", "LAN (local area network) aliases (e.g.: \"lan\"). Must be set along wan-alias.")
	flag.Var(&wanInterfaces, "wan-interface", "WAN (wide area network) interface (e.g.: \"eth0\"). Required if no alias is provided.")
	flag.Var(&lanInterfaces, "lan-interface", "LAN (local area network) interface (e.g.: \"eth1\"). Required if no alias is provided.")
	flag.Var(&lanQueues, "lan-queue", "LAN (local area network) nf queue (e.g.: \"2\"). Required if no alias is provided.")
	flag.Var(&lanAddresses, "lan-mac-address", "LAN (local area network) mac address (e.g.: \"5e:73:2a:c4:53:81\"). Required if no alias is provided.")
	flag.IntVar(&extraIPAddresses, "extra-ip-addresses", 0, "number of local ip addresses to use for the internet network. Must be set along extra-ip-addresses-wan-alias.")
	flag.StringVar(&extraIPAddressesWANAlias, "extra-ip-addresses-wan-alias", "", "WAN (wide area network) alias (e.g.: \"wan\") to attach the IP address to. Must be set along extra-ip-addresses.")

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		return nil, nil, nil, nil, usageError
	}
	flag.Parse()

	if extraIPAddresses > 0 && extraIPAddressesWANAlias != "" {
		wanAlisesInterfaces, err := findInterfacesForAliases([]string{extraIPAddressesWANAlias})
		if err != nil {
			return nil, nil, nil, nil, err
		}
		wanInterface := wanAlisesInterfaces[0]
		addrs, err := wanInterface.Addrs()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		for _, addr := range addrs {
			cidr := addr.String()
			ipAndMask := strings.Split(cidr, "/")
			ip := ipAndMask[0]
			cidrMask := ipAndMask[1]
			hosts, stop := Hosts(cidr)
			defer func() { stop <- nil }()
			for host := range hosts {
				if host == ip {
					continue
				}
				_, err := exec.Command("ping", "-c1", "-t1", host).Output()
				if err != nil {
					err := exec.Command("ip", "addr", "add", fmt.Sprintf("%v/%v", host, cidrMask), "dev", wanInterface.Name).Run()
					if err != nil {
						return nil, nil, nil, nil, err
					}
					extraIPAddresses--
					if extraIPAddresses == 0 {
						break
					}
				}
			}
			if extraIPAddresses > 0 {
				return nil, nil, nil, nil, errExtraIPAddressNoHostFound
			}
		}
	}

	if len(wanAliases) != 0 {
		wanAlisesInterfaces, err := findInterfacesForAliases(wanAliases)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		lanAlisesInterfaces, err := findInterfacesForAliases(lanAliases)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// 34 was randomly selected
		// well, not really randomly, but randomly enough
		baseLANQueue := 34
		for i, wanInterface := range wanAlisesInterfaces {
			err = setupForwardAndQueue(wanInterface.Name, lanAlisesInterfaces[i].Name, baseLANQueue+i)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			wanInterfaces = append(wanInterfaces, wanInterface.Name)
			lanInterfaces = append(lanInterfaces, lanAlisesInterfaces[i].Name)
			lanAddresses = append(lanAddresses, lanAlisesInterfaces[i].HardwareAddr)
			lanQueues = append(lanQueues, baseLANQueue+i)
		}
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
	return lanInterfaces, lanQueues, lanAddresses, wanInterfaces, nil
}

func main() {
	var configString string
	flag.StringVar(&configString, "config", "", "Configuration JSON.")
	lanInterfaces, lanQueues, lanAddresses, wanInterfaces, err := getInterfacesAndQueues()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
	conf := DefaultConfiguration(len(wanInterfaces))
	if configString != "" {
		err = json.Unmarshal([]byte(configString), conf)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error()+"\n")
			os.Exit(1)
		}
	}
	router, err := NewRouter(conf, lanInterfaces, lanQueues, lanAddresses, wanInterfaces)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
	router.Run()
}
