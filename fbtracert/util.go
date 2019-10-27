/**
 * Copyright (c) 2016-present, Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

package fbtracert

import (
	//"fmt"
	"net"
	"sync"
)


type Hop struct {
    SrcAddr string
    SrcName string
    Sent int
    Received int
}


//
// Filter data on input channel
//
func Filter(f func(interface{}) bool, in chan interface{}) chan interface{} {
	out := make(chan interface{})

	go func() {
		for val := range in {
			if f(val) {
				out <- val
			}
		}
	}()

	return out
}

//
// Fork input channel into two, copy data
//
func Fork(in <-chan interface{}) (out1, out2 chan interface{}) {
	out1, out2 = make(chan interface{}), make(chan interface{})

	go func() {
		for val := range in {
			out1 <- val
			out2 <- val
		}
	}()

	return
}

//
// Merge data from multiple channels into one
//
func Merge(cs ...chan ProbeResponse) chan ProbeResponse {
	var wg sync.WaitGroup
	out := make(chan ProbeResponse)

	output := func(c <-chan ProbeResponse) {
		defer wg.Done()
		for val := range c {
			out <- val
		}
	}

	wg.Add(len(cs))
	for _, ch := range cs {
		go output(ch)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

//
// Merge data from multiple channels into one
//
func MergeProbes(cs ...chan Probe) chan Probe {
	var wg sync.WaitGroup
	out := make(chan Probe)

	output := func(c <-chan Probe) {
		defer wg.Done()
		for val := range c {
			out <- val
		}
	}

	wg.Add(len(cs))
	for _, ch := range cs {
		go output(ch)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

//
// Detect a pattern where all samples after
// a sample [i] have lower hit rate than [i]
// this normally indicates a breaking point after [i]
//
func IsLossy(hitRates []float64) bool {
	var found bool
	var segLen int
	for i := 0; i < len(hitRates)-1 && !found; i++ {
		found = true
		segLen = len(hitRates) - i
		for j := i + 1; j < len(hitRates); j++ {
			if hitRates[j] >= hitRates[i] {
				found = false
				break
			}
		}
	}
	// do not alarm on single-hop segment
	if segLen > 2 {
		return found
	}
	return false
}

//
// Normalize rcvd by send count to get the hit rate
//
func NormalizeRcvd(hops []Hop) ([]float64, error) {
//	if len(rcvd) != len(sent) {
//		return nil, fmt.Errorf("Length mismatch for sent/rcvd")
//	}

	result := make([]float64, len(hops))
	for i := range hops {
		result[i] = float64(hops[i].Received) / float64(hops[i].Sent)
	}

	return result, nil
}

// Resolve given hostname/address in the given address family
func ResolveName(dest string, af string) (net.IP, error) {
	addr, err := net.ResolveIPAddr(af, dest)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}
