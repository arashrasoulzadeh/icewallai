package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Packet struct {
	from     string
	to       string
	protocol string
}

var packets []Packet

var (
	device       string = "en0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		printPacketInfo(packet)
	}

}
func printPacketInfo(packet gopacket.Packet) {

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP := fmt.Sprintf("%s", ip.SrcIP)
		dstIP := fmt.Sprintf("%s", ip.DstIP)
		protocol := fmt.Sprintf("%s", ip.Protocol)

		packets = append(packets, Packet{from: srcIP, to: dstIP, protocol: protocol})

		fmt.Printf("%s -> %s over %s\n", srcIP, dstIP, protocol)
	}

}
