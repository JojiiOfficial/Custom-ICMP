package main

import (
	"bufio"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mostlygeek/arp"
)

var reservedIPs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

func isIPv4Valid(ip string) (bool, int) {
	pip := net.ParseIP(ip)
	if pip.To4() == nil {
		return false, 0
	}
	return true, 1
}

func isIPBogon(ip string) bool {
	pip := net.ParseIP(ip)
	for _, reservedIP := range reservedIPs {
		_, subnet, err := net.ParseCIDR(reservedIP)
		if err != nil {
			panic(err)
		}
		if subnet.Contains(pip) {
			return true
		}
	}
	return false
}

func byteToMac(data []byte) string {
	var mac string
	for _, d := range data {
		mac += strconv.FormatInt((int64)(d), 16) + ":"
	}
	return mac[:len(mac)-1]
}

func byteToIP(data []byte) string {
	var ip string
	for _, d := range data {
		ip += strconv.Itoa((int)(d)) + "."
	}
	return ip[:len(ip)-1]
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func ipRemoveSubnet(ip string) string {
	return ip[:strings.Index(ip, "/")]
}

func getRandomMac() string {
	var hexChars = []rune("1234567890abcdef")
	rand.Seed(time.Now().UnixNano())
	s := ""
	for i := 0; i < 6; i++ {
		s += (string)(hexChars[rand.Intn(len(hexChars))])
		rand.Seed(time.Now().UnixNano())
		s += (string)(hexChars[rand.Intn(len(hexChars))]) + ":"
	}
	return s[:len(s)-1]
}

func getGateway() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		for i := 0; i < 1; i++ {
			scanner.Scan()
		}
		tokens := strings.Split(scanner.Text(), "\t")
		gatewayHex := "0x" + tokens[2]
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)
		ipd32 := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)
		ip := net.IP(ipd32).String()
		return ip
	}
	return ""
}

func getMacFromIP(sip string) string {
	exec.Command("ping", "-c1 ", sip).Run()
	return arp.Search(sip)
}
