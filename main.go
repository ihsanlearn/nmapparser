package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
)

// ---------------------------------------------------------------------------
// XML structs (mirrors Nmap XML schema)
// ---------------------------------------------------------------------------

type NmapRun struct {
	XMLName          xml.Name   `xml:"nmaprun"`
	Scanner          string     `xml:"scanner,attr"`
	Args             string     `xml:"args,attr"`
	Start            int64      `xml:"start,attr"`
	StartStr         string     `xml:"startstr,attr"`
	Version          string     `xml:"version,attr"`
	XMLOutputVersion string     `xml:"xmloutputversion,attr"`
	ScanInfo         []ScanInfo `xml:"scaninfo"`
	Verbose          *Level     `xml:"verbose"`
	Debugging        *Level     `xml:"debugging"`
	Hosts            []Host     `xml:"host"`
	PreScript        *Scripts   `xml:"prescript"`
	PostScript       *Scripts   `xml:"postscript"`
	RunStats         *RunStats  `xml:"runstats"`
}

type Level struct {
	Level int `xml:"level,attr"`
}

type ScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices int    `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

type Host struct {
	StartTime   int64        `xml:"starttime,attr"`
	EndTime     int64        `xml:"endtime,attr"`
	Comment     string       `xml:"comment,attr"`
	Status      *Status      `xml:"status"`
	Addresses   []Address    `xml:"address"`
	Hostnames   []Hostname   `xml:"hostnames>hostname"`
	Ports       []Port       `xml:"ports>port"`
	ExtraPorts  []ExtraPort  `xml:"ports>extraports"`
	OS          *OS          `xml:"os"`
	HostScripts []Script     `xml:"hostscript>script"`
	Trace       *Trace       `xml:"trace"`
	Times       *Times       `xml:"times"`
	Distance    *Distance    `xml:"distance"`
	Uptime      *Uptime      `xml:"uptime"`
	TCPSequence *TCPSequence `xml:"tcpsequence"`
}

type Status struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Port struct {
	Protocol string   `xml:"protocol,attr"`
	PortID   int      `xml:"portid,attr"`
	State    *State   `xml:"state"`
	Service  *Service `xml:"service"`
	Scripts  []Script `xml:"script"`
}

type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr"`
	ReasonIP  string `xml:"reason_ip,attr"`
}

type Service struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr"`
	Version   string   `xml:"version,attr"`
	ExtraInfo string   `xml:"extrainfo,attr"`
	Hostname  string   `xml:"hostname,attr"`
	OSType    string   `xml:"ostype,attr"`
	Method    string   `xml:"method,attr"`
	Conf      int      `xml:"conf,attr"`
	Tunnel    string   `xml:"tunnel,attr"`
	Proto     string   `xml:"proto,attr"`
	RPCNum    string   `xml:"rpcnum,attr"`
	LowVer    string   `xml:"lowver,attr"`
	HighVer   string   `xml:"highver,attr"`
	CPEs      []string `xml:"cpe"`
	Scripts   []Script `xml:"script"`
}

type Script struct {
	ID     string        `xml:"id,attr"`
	Output string        `xml:"output,attr"`
	Tables []ScriptTable `xml:"table"`
	Elems  []ScriptElem  `xml:"elem"`
}

type ScriptTable struct {
	Key    string        `xml:"key,attr"`
	Tables []ScriptTable `xml:"table"`
	Elems  []ScriptElem  `xml:"elem"`
}

type ScriptElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type ExtraPort struct {
	State   string        `xml:"state,attr"`
	Count   int           `xml:"count,attr"`
	Reasons []ExtraReason `xml:"extrareasons"`
}

type ExtraReason struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
}

type OS struct {
	PortsUsed     []PortUsed      `xml:"portused"`
	OSMatches     []OSMatch       `xml:"osmatch"`
	OSFingerprint []OSFingerprint `xml:"osfingerprint"`
}

type PortUsed struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortID int    `xml:"portid,attr"`
}

type OSMatch struct {
	Name      string    `xml:"name,attr"`
	Accuracy  int       `xml:"accuracy,attr"`
	Line      int       `xml:"line,attr"`
	OSClasses []OSClass `xml:"osclass"`
}

type OSClass struct {
	Type     string   `xml:"type,attr"`
	Vendor   string   `xml:"vendor,attr"`
	OSFamily string   `xml:"osfamily,attr"`
	OSGen    string   `xml:"osgen,attr"`
	Accuracy int      `xml:"accuracy,attr"`
	CPEs     []string `xml:"cpe"`
}

type OSFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr"`
}

type Scripts struct {
	Scripts []Script `xml:"script"`
}

type Trace struct {
	Port  int    `xml:"port,attr"`
	Proto string `xml:"proto,attr"`
	Hops  []Hop  `xml:"hop"`
}

type Hop struct {
	TTL    int     `xml:"ttl,attr"`
	RTT    float64 `xml:"rtt,attr"`
	IPAddr string  `xml:"ipaddr,attr"`
	Host   string  `xml:"host,attr"`
}

type Times struct {
	SRTT   int `xml:"srtt,attr"`
	RTTVar int `xml:"rttvar,attr"`
	To     int `xml:"to,attr"`
}

type Distance struct {
	Value int `xml:"value,attr"`
}

type Uptime struct {
	Seconds  int    `xml:"seconds,attr"`
	LastBoot string `xml:"lastboot,attr"`
}

type TCPSequence struct {
	Index      int    `xml:"index,attr"`
	Difficulty string `xml:"difficulty,attr"`
	Values     string `xml:"values,attr"`
}

type RunStats struct {
	Finished *Finished `xml:"finished"`
	Hosts    *HostStat `xml:"hosts"`
}

type Finished struct {
	Time     int64   `xml:"time,attr"`
	TimeStr  string  `xml:"timestr,attr"`
	Elapsed  float64 `xml:"elapsed,attr"`
	Summary  string  `xml:"summary,attr"`
	Exit     string  `xml:"exit,attr"`
	ErrorMsg string  `xml:"errormsg,attr"`
}

type HostStat struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// ---------------------------------------------------------------------------
// JSON output structs
// ---------------------------------------------------------------------------

type JSONOutput struct {
	Scanner          string       `json:"scanner,omitempty"`
	Args             string       `json:"args,omitempty"`
	Start            int64        `json:"start,omitempty"`
	StartStr         string       `json:"startstr,omitempty"`
	Version          string       `json:"version,omitempty"`
	XMLOutputVersion string       `json:"xmloutputversion,omitempty"`
	ScanInfo         []ScanInfo   `json:"scaninfo,omitempty"`
	Verbose          *int         `json:"verbose,omitempty"`
	Debugging        *int         `json:"debugging,omitempty"`
	PreScript        []JSONScript `json:"prescript,omitempty"`
	Hosts            []JSONHost   `json:"hosts"`
	PostScript       []JSONScript `json:"postscript,omitempty"`
	RunStats         interface{}  `json:"runstats,omitempty"`
}

type JSONHost struct {
	StartTime   int64        `json:"starttime,omitempty"`
	EndTime     int64        `json:"endtime,omitempty"`
	Status      *Status      `json:"status,omitempty"`
	Addresses   []Address    `json:"addresses,omitempty"`
	Hostnames   []Hostname   `json:"hostnames,omitempty"`
	Ports       []JSONPort   `json:"ports,omitempty"`
	ExtraPorts  []ExtraPort  `json:"extraports,omitempty"`
	OS          *JSONOS      `json:"os,omitempty"`
	HostScripts []JSONScript `json:"hostscripts,omitempty"`
	Traceroute  *Trace       `json:"traceroute,omitempty"`
	Times       *Times       `json:"times,omitempty"`
	Distance    *int         `json:"distance,omitempty"`
	Uptime      *Uptime      `json:"uptime,omitempty"`
	TCPSequence *TCPSequence `json:"tcpsequence,omitempty"`
}

type JSONPort struct {
	Protocol string       `json:"protocol,omitempty"`
	PortID   int          `json:"portid"`
	State    *State       `json:"state,omitempty"`
	Service  *Service     `json:"service,omitempty"`
	Scripts  []JSONScript `json:"scripts,omitempty"`
}

type JSONScript struct {
	ID       string            `json:"id,omitempty"`
	Output   string            `json:"output,omitempty"`
	Tables   []JSONScriptTable `json:"tables,omitempty"`
	Elements map[string]string `json:"elements,omitempty"`
}

type JSONScriptTable struct {
	Key  string        `json:"key,omitempty"`
	Rows []interface{} `json:"rows,omitempty"`
}

type JSONOS struct {
	PortsUsed    []PortUsed `json:"portused,omitempty"`
	Matches      []OSMatch  `json:"matches,omitempty"`
	Fingerprints []string   `json:"fingerprints,omitempty"`
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

func convertScript(s Script) JSONScript {
	js := JSONScript{ID: s.ID, Output: s.Output}
	for _, t := range s.Tables {
		js.Tables = append(js.Tables, convertScriptTable(t))
	}
	if len(s.Elems) > 0 {
		js.Elements = make(map[string]string)
		for i, e := range s.Elems {
			key := e.Key
			if key == "" {
				key = fmt.Sprintf("elem_%d", i)
			}
			js.Elements[key] = strings.TrimSpace(e.Value)
		}
	}
	return js
}

func convertScriptTable(t ScriptTable) JSONScriptTable {
	jt := JSONScriptTable{Key: t.Key}
	for _, e := range t.Elems {
		key := e.Key
		if key == "" {
			key = "value"
		}
		jt.Rows = append(jt.Rows, map[string]string{key: strings.TrimSpace(e.Value)})
	}
	for _, sub := range t.Tables {
		jt.Rows = append(jt.Rows, convertScriptTable(sub))
	}
	return jt
}

func convertHost(h Host) JSONHost {
	jh := JSONHost{
		StartTime:   h.StartTime,
		EndTime:     h.EndTime,
		Status:      h.Status,
		Addresses:   h.Addresses,
		Hostnames:   h.Hostnames,
		ExtraPorts:  h.ExtraPorts,
		Times:       h.Times,
		Traceroute:  h.Trace,
		Uptime:      h.Uptime,
		TCPSequence: h.TCPSequence,
	}
	if h.Distance != nil {
		v := h.Distance.Value
		jh.Distance = &v
	}
	for _, p := range h.Ports {
		jp := JSONPort{Protocol: p.Protocol, PortID: p.PortID, State: p.State, Service: p.Service}
		for _, s := range p.Scripts {
			jp.Scripts = append(jp.Scripts, convertScript(s))
		}
		jh.Ports = append(jh.Ports, jp)
	}
	if h.OS != nil {
		jos := &JSONOS{PortsUsed: h.OS.PortsUsed, Matches: h.OS.OSMatches}
		for _, fp := range h.OS.OSFingerprint {
			jos.Fingerprints = append(jos.Fingerprints, fp.Fingerprint)
		}
		jh.OS = jos
	}
	for _, s := range h.HostScripts {
		jh.HostScripts = append(jh.HostScripts, convertScript(s))
	}
	return jh
}

func convertScripts(ss []Script) []JSONScript {
	var out []JSONScript
	for _, s := range ss {
		out = append(out, convertScript(s))
	}
	return out
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

func filterByState(hosts []JSONHost, state string) []JSONHost {
	for i := range hosts {
		var filtered []JSONPort
		for _, p := range hosts[i].Ports {
			if p.State != nil && p.State.State == state {
				filtered = append(filtered, p)
			}
		}
		hosts[i].Ports = filtered
	}
	return hosts
}

type HostSummary struct {
	Addresses []Address  `json:"addresses"`
	Hostnames []Hostname `json:"hostnames"`
	Status    *Status    `json:"status,omitempty"`
	OS        string     `json:"os,omitempty"`
}

func hostsOnly(hosts []JSONHost) []HostSummary {
	var out []HostSummary
	for _, h := range hosts {
		s := HostSummary{Addresses: h.Addresses, Hostnames: h.Hostnames, Status: h.Status}
		if h.OS != nil && len(h.OS.Matches) > 0 {
			s.OS = h.OS.Matches[0].Name
		}
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------------
// Summary printer
// ---------------------------------------------------------------------------

func printSummary(out JSONOutput) {
	var elapsed float64
	var up int
	if rs, ok := out.RunStats.(*RunStats); ok && rs != nil {
		if rs.Finished != nil {
			elapsed = rs.Finished.Elapsed
		}
		if rs.Hosts != nil {
			up = rs.Hosts.Up
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(os.Stderr, "  Nmap %s  |  %s\n", out.Version, out.StartStr)
	fmt.Fprintf(os.Stderr, "  Args: %s\n", out.Args)
	fmt.Fprintf(os.Stderr, "  Elapsed: %.2fs  |  Hosts up: %d\n", elapsed, up)
	fmt.Fprintf(os.Stderr, "%s\n\n", strings.Repeat("=", 60))

	for _, h := range out.Hosts {
		var addrs []string
		for _, a := range h.Addresses {
			if a.AddrType != "mac" {
				addrs = append(addrs, a.Addr)
			}
		}
		var names []string
		for _, hn := range h.Hostnames {
			if hn.Name != "" {
				names = append(names, hn.Name)
			}
		}
		state := "?"
		if h.Status != nil {
			state = h.Status.State
		}
		label := strings.Join(addrs, ", ")
		if len(names) > 0 {
			label += fmt.Sprintf("  (%s)", strings.Join(names, ", "))
		}
		fmt.Fprintf(os.Stderr, "HOST: %s  [%s]\n", label, state)
		for _, p := range h.Ports {
			pstate := "?"
			if p.State != nil {
				pstate = p.State.State
			}
			svcName, product, version := "", "", ""
			if p.Service != nil {
				svcName = p.Service.Name
				product = p.Service.Product
				version = p.Service.Version
			}
			svcStr := strings.Join(filterEmpty([]string{svcName, product, version}), " ")
			fmt.Fprintf(os.Stderr, "  %6d/%-4s %-12s %s\n", p.PortID, p.Protocol, pstate, svcStr)
		}
		fmt.Fprintln(os.Stderr)
	}
}

func filterEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	outputFile := flag.StringP("output", "o", "", "Write JSON to file (default: stdout)")
	compact := flag.Bool("compact", false, "Compact JSON output")
	filterState := flag.String("filter-state", "", "Only include ports with this state (e.g. open, closed, filtered)")
	hostsOnlyF := flag.Bool("hosts-only", false, "Return condensed host-level summary")
	summary := flag.Bool("summary", false, "Print human-readable summary to stderr")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `nmapparser — convert Nmap XML output to JSON

Usage:
  nmapparser [flags] <nmap.xml>
  nmapparser [flags] -        # read from stdin

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  nmapparser scan.xml
  nmapparser scan.xml -o result.json
  nmapparser --filter-state open scan.xml
  nmapparser scan.xml --hosts-only
  nmapparser scan.xml --summary -o result.json
  nmap -sS -oX - 192.168.1.1 | nmapparser -
  nmapparser scan.xml --compact | jq '.hosts[].ports[]'
`)
	}

	// pflag supports flags placed ANYWHERE — before or after the input file
	flag.CommandLine.SetInterspersed(true)
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	// --- Read input ---
	var xmlData []byte
	var err error

	input := flag.Arg(0)
	if input == "-" {
		xmlData, err = io.ReadAll(os.Stdin)
	} else {
		xmlData, err = os.ReadFile(input)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}

	// --- Parse XML ---
	var nmap NmapRun
	if err := xml.Unmarshal(xmlData, &nmap); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to parse XML: %v\n", err)
		os.Exit(1)
	}

	// --- Build output ---
	out := JSONOutput{
		Scanner:          nmap.Scanner,
		Args:             nmap.Args,
		Start:            nmap.Start,
		StartStr:         nmap.StartStr,
		Version:          nmap.Version,
		XMLOutputVersion: nmap.XMLOutputVersion,
		ScanInfo:         nmap.ScanInfo,
	}
	if nmap.Verbose != nil {
		v := nmap.Verbose.Level
		out.Verbose = &v
	}
	if nmap.Debugging != nil {
		d := nmap.Debugging.Level
		out.Debugging = &d
	}
	if nmap.PreScript != nil {
		out.PreScript = convertScripts(nmap.PreScript.Scripts)
	}
	if nmap.PostScript != nil {
		out.PostScript = convertScripts(nmap.PostScript.Scripts)
	}
	if nmap.RunStats != nil {
		out.RunStats = nmap.RunStats
	}
	for _, h := range nmap.Hosts {
		out.Hosts = append(out.Hosts, convertHost(h))
	}

	// --- Filters ---
	if *filterState != "" {
		out.Hosts = filterByState(out.Hosts, *filterState)
	}

	// --- Summary ---
	if *summary {
		printSummary(out)
	}

	// --- Serialize ---
	var jsonBytes []byte
	var outputData interface{} = out
	if *hostsOnlyF {
		outputData = hostsOnly(out.Hosts)
	}

	if *compact {
		jsonBytes, err = json.Marshal(outputData)
	} else {
		jsonBytes, err = json.MarshalIndent(outputData, "", "  ")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] JSON marshal: %v\n", err)
		os.Exit(1)
	}

	// --- Output ---
	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, jsonBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Write file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[+] JSON written to: %s\n", *outputFile)
	} else {
		fmt.Println(string(jsonBytes))
	}
}
