/**
 * Copyright (c) 2016-present, Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

package fbtracert

import (
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/golang/glog"
)

const (
	icmpHdrSize      int = 8
	minTCPHdrSize    int = 20
	maxTCPHdrSize    int = 60
	minIP4HeaderSize int = 20
	maxIP4HeaderSize int = 60
	ip6HeaderSize    int = 40
)

// Probe is emitted by sender
type Probe struct {
	SrcPort int
	TTL     int
}

type ProbeResponse struct {
    Probe
    SrcAddr net.IP
    SrcName string
    Protocol string
    Flags string
    RecvTTL int
    RTT uint32
}

// TCPReceiver Feeds on TCP RST messages we receive from the end host; we use lots of parameters to check if the incoming packet
// is actually a response to our probe. We create TCPResponse structs and emit them on the output channel
func TCPReceiver(done <-chan struct{}, af string, srcAddr net.IP, targetAddr string, probePortStart, probePortEnd, targetPort, maxTTL int) (chan ProbeResponse, error) {
	glog.V(2).Infoln("TCPReceiver starting...")

	conn, err := net.ListenPacket(af+":tcp", srcAddr.String())
	if err != nil {
		return nil, err
	}

	// we'll be writing the TCPResponse structs to this channel
	out := make(chan ProbeResponse)

	// IP + TCP header, this channel is fed from the socket
	recv := make(chan ProbeResponse)
	go func() {
		ipHdrSize := 0 // no IPv6 header present on TCP packets received on the raw socket
		if af == "ip4" {
			// IPv4 header is always included with the ipv4 raw socket receive
			ipHdrSize = minIP4HeaderSize
		}
		packet := make([]byte, ipHdrSize+maxTCPHdrSize)

		for {
			n, from, err := conn.ReadFrom(packet)
			if err != nil {
				break // parent has closed the socket likely
			}

			// IP + TCP header size
			if n < ipHdrSize+minTCPHdrSize {
				continue
			}

			// is that from the target port we expect?
			tcpHdr := parseTCPHeader(packet[ipHdrSize:n])
			if int(tcpHdr.Source) != targetPort {
				continue
			}

			// is that TCP RST TCP ACK?
			if tcpHdr.Flags&RST != RST && tcpHdr.Flags&ACK != ACK {
				continue
			}

			// is that from our target?
			if from.String() != targetAddr {
				continue
			}

			glog.V(4).Infof("Received TCP response message %d: %x\n", n, packet[:n])

			// we extract the original TTL and timestamp from the ack number
			ackNum := tcpHdr.AckNum - 1
			ttl := int(ackNum >> 24)

			if ttl > maxTTL || ttl < 1 {
				continue
			}

			// recover the time-stamp from the ack #
			ts := ackNum & 0x00ffffff
			now := uint32(time.Now().UnixNano()/(1000*1000)) & 0x00ffffff

			// received timestamp is higher than local time; it is possible
			// that ts == now, since our clock resolution is coarse
			if ts > now {
				continue
			}

			recv <- ProbeResponse{Probe: Probe{SrcPort: int(tcpHdr.Destination), TTL: ttl}, Protocol: "tcp", SrcAddr: net.ParseIP(from.String()), RTT: now - ts}
		}
	}()

	go func() {
		defer conn.Close()
		defer close(out)
		for {
			select {
			case response := <-recv:
				out <- response
			case <-done:
				glog.V(2).Infoln("TCPReceiver terminating...")
				return
			}
		}
	}()

	return out, nil
}

// ICMPReceiver runs on its own collecting ICMP responses until its explicitly told to stop
func ICMPReceiver(done <-chan struct{}, af string, srcAddr net.IP) (chan ProbeResponse, error) {
	var (
		minInnerIPHdrSize int
		icmpMsgType       byte
		listenNet         string
	)

	switch af {
	case "ip4":
		minInnerIPHdrSize = minIP4HeaderSize // the size of the original IPv4 header that was on the TCP packet sent out
		icmpMsgType = 11                     // time to live exceeded
		listenNet = "ip4:1"                  // IPv4 ICMP proto number
	case "ip6":
		minInnerIPHdrSize = ip6HeaderSize // the size of the original IPv4 header that was on the TCP packet sent out
		icmpMsgType = 3                   // time to live exceeded
		listenNet = "ip6:58"              // IPv6 ICMP proto number
	default:
		return nil, fmt.Errorf("sender: unsupported network %q", af)
	}

	conn, err := icmp.ListenPacket(listenNet, srcAddr.String())
	if err != nil {
		return nil, err
	}

	glog.V(2).Infoln("ICMPReceiver is starting...")

	recv := make(chan ProbeResponse)

	go func() {
		// TODO: remove hardcode; 20 bytes for IP header, 8 bytes for ICMP header, 8 bytes for TCP header
		packet := make([]byte, icmpHdrSize+maxIP4HeaderSize+maxTCPHdrSize)
		for {
			n, from, err := conn.ReadFrom(packet)
			if err != nil {
				break
			}
			// extract the 8 bytes of the original TCP header
			if n < icmpHdrSize+minInnerIPHdrSize+minTCPHdrSize {
				continue
			}
			// not TTL exceeded
			if packet[0] != icmpMsgType || packet[1] != 0 {
				continue
			}
			glog.V(4).Infof("Received ICMP response message %d: %x\n", n, packet[:n])
			tcpHdr := parseTCPHeader(packet[icmpHdrSize+minInnerIPHdrSize : n])

			// extract TTL bits from the ISN
			ttl := int(tcpHdr.SeqNum) >> 24

			// extract the timestamp from the ISN
			ts := tcpHdr.SeqNum & 0x00ffffff
			// scale the current time
			now := uint32(time.Now().UnixNano()/(1000*1000)) & 0x00ffffff
			recv <- ProbeResponse{Probe: Probe{SrcPort: int(tcpHdr.Source), TTL: ttl}, Protocol: "icmp", SrcAddr: net.ParseIP(from.String()), RTT: now - ts}
		}
	}()

	out := make(chan ProbeResponse)
	go func() {
		defer conn.Close()
		defer close(out)
		for {
			select {
			// read ICMP struct
			case response := <-recv:
				out <- response
			case <-done:
				glog.V(2).Infoln("ICMPReceiver done")
				return
			}
		}
	}()

	return out, nil
}

// FIXME
// Resolver resolves names in incoming ICMPResponse messages
// Everything else is passed through as is
func Resolver(input chan ProbeResponse) (chan ProbeResponse, error) {
	out := make(chan ProbeResponse)
	go func() {
		defer close(out)

		for resp := range input {
            names, err := net.LookupAddr(resp.SrcAddr.String())
            if err != nil {
                resp.SrcName = resp.SrcAddr.String()
            } else {
                resp.SrcName = names[0]
            }
            out <- resp
		}
	}()
	return out, nil
}

// Sender generates TCP SYN packet probes with given TTL at given packet per second rate
// The packet descriptions are published to the output channel as Probe messages
// As a side effect, the packets are injected into raw socket
func Sender(done <-chan struct{}, srcAddr net.IP, af, dest string, dstPort, baseSrcPort, maxSrcPorts, maxIters, ttl, pps, tos int) (chan Probe, error) {
	var err error

	out := make(chan Probe)

	glog.V(2).Infof("Sender for TTL %d starting\n", ttl)

	dstAddr, err := ResolveName(dest, af)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenPacket(af+":tcp", srcAddr.String())
	if err != nil {
		return nil, err
	}

	switch af {
	case "ip4":
		conn := ipv4.NewPacketConn(conn)
		if err := conn.SetTTL(ttl); err != nil {
			return nil, err
		}
		if err := conn.SetTOS(tos); err != nil {
			return nil, err
		}
	case "ip6":
		conn := ipv6.NewPacketConn(conn)
		if err := conn.SetHopLimit(ttl); err != nil {
			return nil, err
		}
		if runtime.GOOS == "windows" {
			glog.Infoln("Setting IPv6 traffic class not supported on Windows")
			break
		}
		if err := conn.SetTrafficClass(tos); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("sender: unsupported network %q", af)
	}

	// spawn a new goroutine and return the channel to be used for reading
	go func() {
		defer conn.Close()
		defer close(out)

		delay := time.Duration(1000/pps) * time.Millisecond

		for i := 0; i < maxSrcPorts*maxIters; i++ {
			srcPort := baseSrcPort + i%maxSrcPorts
			now := uint32(time.Now().UnixNano()/(1000*1000)) & 0x00ffffff
			seqNum := ((uint32(ttl) & 0xff) << 24) | (now & 0x00ffffff)
			packet := makeTCPHeader(af, srcAddr, dstAddr, srcPort, dstPort, seqNum)

			if _, err := conn.WriteTo(packet, &net.IPAddr{IP: dstAddr}); err != nil {
				glog.Errorf("Error sending packet %s\n", err)
				break
			}

			probe := Probe{SrcPort: srcPort, TTL: ttl}
			start := time.Now() // grab time before blocking on send channel
			select {
			case out <- probe:
				end := time.Now()
				jitter := time.Duration(((rand.Float64()-0.5)/20)*1000/float64(pps)) * time.Millisecond
				if end.Sub(start) < delay+jitter {
					time.Sleep(delay + jitter - (end.Sub(start)))
				}
			case <-done:
				glog.V(2).Infof("Sender for TTL %d exiting prematurely\n", ttl)
				return
			}
		}
		glog.V(2).Infoln("Sender done")
	}()

	return out, nil
}
