package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	snapshotLen int32 = 2048
	promiscouos bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	buffer      gopacket.SerializeBuffer
	options     gopacket.SerializeOptions

	device  = *kingpin.Flag("Interface", "the interface to use for sending the packet").Short('i').Default("wlp2s0").String()
	sIP     = *kingpin.Flag("sourceIP", "source IP address").Short('s').String()
	dIP     = *kingpin.Flag("destIP", "dest IP address").Short('d').Required().String()
	sMac    = *kingpin.Flag("sMAC", "source MAC address").Short('S').String()
	dMac    = *kingpin.Flag("dMAC", "destination MAC address").Required().Short('D').String()
	payload = *kingpin.Flag("payload", "payload for the ICMP packet").Short('p').String()
	count   = *kingpin.Flag("count", "count of ping pakets").Short('c').Int()
)

func init() {
	var showNICs bool
	for _, arg := range os.Args {
		if arg == "--listNICs" {
			showNICs = true
		}
	}
	if showNICs {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Devices found:")
		fmt.Println("")
		for _, device := range devices {
			fmt.Println(device.Name + ":")
			fmt.Println("\tDevices addresses: ", device.Description)
			for _, address := range device.Addresses {
				fmt.Println("\t- IP address: ", address.IP)
				fmt.Println("\t- Subnet mask: ", address.Netmask)
			}
			fmt.Println("")
		}
		os.Exit(0)
		return
	}

	kingpin.Parse()

	addr, err := net.InterfaceByName(device)
	if err != nil {
		fmt.Println("Error setting up the interface: ", device)
		os.Exit(1)
		return
	}
	addrs, err := addr.Addrs()
	if err != nil {
		fmt.Println("Erorr getting interface address!")
		os.Exit(1)
		return
	}

	if len(sIP) == 0 {
		sIP = ipRemoveSubnet(addrs[0].String())
	}
	if len(sMac) == 0 {
		sMac = addr.HardwareAddr.String()
	}

	if len(dIP) == 0 {
		fmt.Println("You need to specify the destination IP address!")
		os.Exit(1)
		return
	}
	if len(dMac) == 0 {
		fmt.Println("You need to specify the destination MAC address!")
		os.Exit(1)
		return
	}
}

func main() {
	handle, err = pcap.OpenLive(device, snapshotLen, promiscouos, timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoRequest << 8,
		Id:       (uint16)(os.Getpid() & 0xffff),
		Seq:      1,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      128,
		Protocol: layers.IPProtocolICMPv4,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    net.ParseIP(sIP),
		DstIP:    net.ParseIP(dIP),
	}

	shw, err := net.ParseMAC(sMac)
	if err != nil {
		fmt.Println("Error parsing src-mac")
		return
	}
	dhw, err := net.ParseMAC(dMac)
	if err != nil {
		fmt.Println("Error parsing dest-mac")
		return
	}

	ethLayer := &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       shw,
		DstMAC:       dhw,
	}
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethLayer,
		ipLayer,
		icmpLayer,
		gopacket.Payload([]byte(payload)),
	)
	for i := 0; i < count; i++ {
		err = handle.WritePacketData(buffer.Bytes())
		if err != nil {
			fmt.Println("Error sending ping")
		} else {
			fmt.Printf("Packet %d sent successfully\n", i+1)
		}
	}
}
