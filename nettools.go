package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

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
