package fbtracert

// Report defines a JSON report from go/fbtracert
type Report struct {
	// The path map
	Paths map[string] /* SrcPort */ []string /* path hops */
	// Probe count sent per source port/hop name
	Sent map[string][]int
	// Probe count received per source port/hop name
	Rcvd map[string][]int
}

func NewReport() (report Report) {
	report.Paths = make(map[string][]string)
	report.Sent = make(map[string][]int)
	report.Rcvd = make(map[string][]int)

	return report
}
