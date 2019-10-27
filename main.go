package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/facebook/fbtracert/fbtracert"
	"github.com/golang/glog"
	//"github.com/olekukonko/tablewriter"
	"net"
	//"os"
	"time"
)

//
// Command line flags
//
var maxTTL = flag.Int("maxTTL", 30, "The maximum ttl to use")
var minTTL = flag.Int("minTTL", 1, "The ttl to start at")
var maxSrcPorts = flag.Int("maxSrcPorts", 256, "The maximum number of source ports to use")
var maxTime = flag.Int("maxTime", 60, "The time to run the process for")
var targetPort = flag.Int("targetPort", 22, "The target port to trace to")
var probeRate = flag.Int("probeRate", 96, "The probe rate per ttl layer")
var tosValue = flag.Int("tosValue", 140, "The TOS/TC to use in probes")
var numResolvers = flag.Int("numResolvers", 32, "The number of DNS resolver goroutines")
var addrFamily = flag.String("addrFamily", "ip4", "The address family (ip4/ip6) to use for testing")
var maxColumns = flag.Int("maxColumns", 4, "Maximum number of columns in report tables")
var showAll = flag.Bool("showAll", false, "Show all paths, regardless of loss detection")
var srcAddr = flag.String("srcAddr", "", "The source address for pings, default to auto-discover")
var jsonOutput = flag.Bool("jsonOutput", false, "Output raw JSON data")
var baseSrcPort = flag.Int("baseSrcPort", 32768, "The base source port to start probing from")

//
// Discover the source address for pinging
//
func getSourceAddr(af string, srcAddr string) (net.IP, error) {

	if srcAddr != "" {
		addr, err := net.ResolveIPAddr(*addrFamily, srcAddr)
		if err != nil {
			return nil, err
		}
		return addr.IP, nil
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
			if (ipnet.IP.To4() != nil && af == "ip4") || (ipnet.IP.To4() == nil && af == "ip6") {
				return ipnet.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("Could not find a source address in af %s", af)
}

func main() {
	flag.Parse()
	if flag.Arg(0) == "" {
		fmt.Println("Must specify a target")
		return
	}
	target := flag.Arg(0)

	var probes []chan fbtracert.Probe

	numIters := int(*maxTime * *probeRate / *maxSrcPorts)

	if numIters <= 1 {
		fmt.Println("Number of iterations too low, increase probe rate / run time or decrease src port range...")
		return
	}

	source, err := getSourceAddr(*addrFamily, *srcAddr)

	if err != nil {
		fmt.Println("Could not identify a source address to trace from")
		return
	}
	fmt.Println(fmt.Sprintf("Using as source address: %s", source.String()))

	fmt.Println(fmt.Sprintf("Starting fbtracert with %d probes per second/ttl, base src port %d and with the port span of %d", *probeRate, *baseSrcPort, *maxSrcPorts))
	if flag.Lookup("logtostderr").Value.String() != "true" {
		fmt.Println("Use '-logtostderr=true' cmd line option to see GLOG output")
	}

	// this will catch senders quitting - we have one sender per ttl
	senderDone := make([]chan struct{}, *maxTTL)
	for ttl := *minTTL; ttl <= *maxTTL; ttl++ {
		senderDone[ttl-1] = make(chan struct{})
		c, err := fbtracert.Sender(senderDone[ttl-1], source, *addrFamily, target, *targetPort, *baseSrcPort, *maxSrcPorts, numIters, ttl, *probeRate, *tosValue)
		if err != nil {
			glog.Errorf("Failed to start sender for ttl %d, %s", ttl, err)
			if err.Error() == "operation not permitted" {
				glog.Error(" -- are you running with the correct privileges?")
			}
			return
		}
		probes = append(probes, c)
	}

	// channel to tell receivers to stop
	recvDone := make(chan struct{})

	// collect ICMP unreachable messages for our probes
	icmpResp, err := fbtracert.ICMPReceiver(recvDone, *addrFamily, source)
	if err != nil {
        glog.Errorln("Error in setting up ICMP receivers")
		return
	}

	// collect TCP RST's from the target
	targetAddr, err := fbtracert.ResolveName(target, *addrFamily)
	tcpResp, err := fbtracert.TCPReceiver(recvDone, *addrFamily, source, targetAddr.String(), *baseSrcPort, *baseSrcPort+*maxSrcPorts, *targetPort, *maxTTL)
	if err != nil {
        glog.Errorln("Error in setting up TCP receiver")
		return
	}

	// add DNS name resolvers to the mix
	var resolved []chan fbtracert.ProbeResponse
	unresolved := fbtracert.Merge(tcpResp, icmpResp)

	for i := 0; i < *numResolvers; i++ {
		c, err := fbtracert.Resolver(unresolved)
		if err != nil {
			return
		}
		resolved = append(resolved, c)
	}

	// maps that store various counters per source port/ttl
	// e..g sent, for every soruce port, contains vector
	// of sent packets for each TTL
	//sent := make(map[int] /*src Port */ []int /* pkts sent */)
	//rcvd := make(map[int] /*src Port */ []int /* pkts rcvd */)
	hops := make(map[int] /*src Port */ []fbtracert.Hop /* hop name */)

	for srcPort := *baseSrcPort; srcPort < *baseSrcPort+*maxSrcPorts; srcPort++ {
		hops[srcPort] = make([]fbtracert.Hop, *maxTTL)
		//hops[srcPort][*maxTTL-1] = target

		for i := 0; i < *maxTTL; i++ {
			hops[srcPort][i].SrcAddr = "?"
			hops[srcPort][i].SrcName = "?"
		}
	}

	// collect all probe specs emitted by senders
	// once all senders terminate, tell receivers to quit too
	go func() {
		for probe := range fbtracert.MergeProbes(probes...) {
			//probe := val.(fbtracert.Probe)
			hops[probe.SrcPort][probe.TTL-1].Sent++
		}
		glog.V(2).Infoln("All senders finished!")
		// give receivers time to catch up on in-flight data
		time.Sleep(2 * time.Second)
		// tell receivers to stop receiving
		close(recvDone)
	}()

	// this store DNS names of all nodes that ever replied to us
	var names []string

	// src ports that changed their paths in process of tracing
	var flappedPorts = make(map[int]bool)

	lastClosed := *maxTTL
	for resp := range fbtracert.Merge(resolved...) {
		switch resp.Protocol {
		case "icmp":
			//resp := val.(fbtracert.ICMPResponse)
			hops[resp.SrcPort][resp.TTL-1].Received++
			currName := hops[resp.SrcPort][resp.TTL-1].SrcName
			if currName != "?" && currName != resp.SrcName {
				glog.V(2).Infof("%d: Source port %d flapped at ttl %d from: %s to %s\n", time.Now().UnixNano()/(1000*1000), resp.SrcPort, resp.TTL, currName, resp.SrcName)
				flappedPorts[resp.SrcPort] = true
			}
			hops[resp.SrcPort][resp.TTL-1].SrcName = resp.SrcName
			hops[resp.SrcPort][resp.TTL-1].SrcAddr = resp.SrcAddr.String()
			// accumulate all names for processing later
			// XXX: we may have duplicates, which is OK,
			// but not very efficient
			names = append(names, resp.SrcName)
		case "tcp":
			//resp := val.(fbtracert.TCPResponse)
			// stop all senders sending above this ttl, since they are not needed
			// XXX: this is not always optimal, i.e. we may receive TCP RST for
			// a port mapped to a short WAN path, and it would tell us to terminate
			// probing at higher TTL, thus cutting visibility on "long" paths
			// however, this mostly concerned that last few hops...
			for i := resp.TTL; i < lastClosed; i++ {
				close(senderDone[i])
			}
			// update the last closed ttl, so we don't double-close the channels
			if resp.TTL < lastClosed {
				lastClosed = resp.TTL
			}
			hops[resp.SrcPort][resp.TTL-1].Received++
			hops[resp.SrcPort][resp.TTL-1].SrcName = resp.SrcName
			hops[resp.SrcPort][resp.TTL-1].SrcAddr = resp.SrcAddr.String()
		}
	}

	for _, hopVector := range hops {
		for i := range hopVector {
			// truncate lists once we hit the target address
			if hopVector[i].SrcAddr == targetAddr.String() && i < *maxTTL-1 {
				hopVector = hopVector[:i+1]
				break
			}
		}
	}

	if len(flappedPorts) > 0 {
		glog.Infof("A total of %d ports out of %d changed their paths while tracing\n", len(flappedPorts), *maxSrcPorts)
	}

	lossyPathHops := make(map[int] /*src port*/ []fbtracert.Hop)

	// process the accumulated data, find and output lossy paths
	for port, hopVector := range hops {
		if flappedPorts[port] {
			continue
		}
        norm, err := fbtracert.NormalizeRcvd(hopVector)

        if err != nil {
            glog.Errorf("Could not normalize %v", hopVector)
            continue
        }

        if fbtracert.IsLossy(norm) || *showAll {
/*
            hosts := make([]string, len(norm))
            for i := range norm {
                hosts[i] = hops[port][i]
            }
*/
            lossyPathHops[port] = hopVector
        }
	}

	if len(lossyPathHops) > 0 {
		if *jsonOutput {
			printLossyPathsJSON(lossyPathHops, lastClosed+1)
		//} else {
			//printLossyPaths(lossyPathHops, *maxColumns, lastClosed+1)
		}
		return
	}
	glog.Infof("Did not find any faulty paths\n")
}

//
// print the paths reported as having losses
//
/*
func printLossyPaths(hops map[int][]Hop, maxColumns, maxTTL int) {
	var allPorts []int

	for srcPort := range hops {
		allPorts = append(allPorts, srcPort)
	}

	// split in multiple tables to fit the columns on the screen
	for i := 0; i < len(allPorts)/maxColumns; i++ {
		data := make([][]string, maxTTL)
		table := tablewriter.NewWriter(os.Stdout)
		header := []string{"TTL"}

		maxOffset := (i + 1) * maxColumns
		if maxOffset > len(allPorts) {
			maxOffset = len(allPorts)
		}

		for _, srcPort := range allPorts[i*maxColumns : maxOffset] {
			header = append(header, fmt.Sprintf("port: %d", srcPort), fmt.Sprintf("sent/rcvd"))
		}

		table.SetHeader(header)

		for ttl := 0; ttl < maxTTL-1; ttl++ {
			data[ttl] = make([]string, 2*(maxOffset-i*maxColumns)+1)
			data[ttl][0] = fmt.Sprintf("%d", ttl+1)
			for j, srcPort := range allPorts[i*maxColumns : maxOffset] {
				data[ttl][2*j+1] = hops[srcPort][ttl]
				data[ttl][2*j+2] = fmt.Sprintf("%02d/%02d", sent[srcPort][ttl], rcvd[srcPort][ttl])
			}
		}

		for _, v := range data {
			table.Append(v)
		}

		table.Render()
		fmt.Println("")
	}
}
*/

//
// Raw Json output for external program to analyze
//
func printLossyPathsJSON(hops map[int][]fbtracert.Hop, maxTTL int) {
/*
	var report = fbtracert.NewReport()

	for srcPort, path := range hops {
		report.Paths[fmt.Sprintf("%d", srcPort)] = path
		report.Sent[fmt.Sprintf("%d", srcPort)] = sent[srcPort]
		report.Rcvd[fmt.Sprintf("%d", srcPort)] = rcvd[srcPort]
	}
*/

	b, err := json.MarshalIndent(hops, "", "\t")
	if err != nil {
		glog.Errorf("Could not generate JSON %s", err)
		return
	}
	fmt.Println(string(b))
}
