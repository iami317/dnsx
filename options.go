package dnsx

import (
	"errors"
	"github.com/iami317/logx"
	"math"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goflags"
)

type Options struct {
	Resolvers    string
	Domains      string
	WordList     string
	Threads      int
	RateLimit    int
	Retries      int
	OutputFormat string
	//OutputFile        string
	Raw               bool
	Silent            bool
	Verbose           bool
	Response          bool
	ResponseOnly      bool
	A                 bool
	AAAA              bool
	NS                bool
	CNAME             bool
	PTR               bool
	MX                bool
	SOA               bool
	ANY               bool
	TXT               bool
	SRV               bool
	AXFR              bool
	JSON              bool
	OmitRaw           bool
	Trace             bool
	TraceMaxRecursion int
	WildcardThreshold int
	WildcardDomain    string
	//ShowStatistics    bool
	rcodes      map[int]struct{}
	RCode       string
	hasRCodes   bool
	Stream      bool
	CAA         bool
	QueryAll    bool
	ExcludeType []string
	OutputCDN   bool
	OnResult    ResultFn // callback on final host result
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`一个快速且多用途的 DNS 工具包，允许使用 RetryableDNS 库运行多个探测器。`)

	flagSet.CreateGroup("input", "输入",
		flagSet.StringVarP(&options.Domains, "domain", "d", "", "list of domain to bruteforce (file or comma separated or stdin)"),
		flagSet.StringVarP(&options.WordList, "wordlist", "w", "", "list of words to bruteforce (file or comma separated or stdin)"),
	)

	queries := goflags.AllowdTypes{
		"none":  goflags.EnumVariable(0),
		"a":     goflags.EnumVariable(1),
		"aaaa":  goflags.EnumVariable(2),
		"cname": goflags.EnumVariable(3),
		"ns":    goflags.EnumVariable(4),
		"txt":   goflags.EnumVariable(5),
		"srv":   goflags.EnumVariable(6),
		"ptr":   goflags.EnumVariable(7),
		"mx":    goflags.EnumVariable(8),
		"soa":   goflags.EnumVariable(9),
		"axfr":  goflags.EnumVariable(10),
		"caa":   goflags.EnumVariable(11),
		"any":   goflags.EnumVariable(12),
	}

	flagSet.CreateGroup("query", "查询",
		flagSet.BoolVar(&options.A, "a", false, "query A record (default)"),
		flagSet.BoolVar(&options.AAAA, "aaaa", false, "query AAAA record"),
		flagSet.BoolVar(&options.CNAME, "cname", false, "query CNAME record"),
		flagSet.BoolVar(&options.NS, "ns", false, "query NS record"),
		flagSet.BoolVar(&options.TXT, "txt", false, "query TXT record"),
		flagSet.BoolVar(&options.SRV, "srv", false, "query SRV record"),
		flagSet.BoolVar(&options.PTR, "ptr", false, "query PTR record"),
		flagSet.BoolVar(&options.MX, "mx", false, "query MX record"),
		flagSet.BoolVar(&options.SOA, "soa", false, "query SOA record"),
		flagSet.BoolVar(&options.ANY, "any", false, "query ANY record"),
		flagSet.BoolVar(&options.AXFR, "axfr", false, "query AXFR"),
		flagSet.BoolVar(&options.CAA, "caa", false, "query CAA record"),
		flagSet.BoolVarP(&options.QueryAll, "recon", "all", false, "query all the dns records (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa)"),
		flagSet.EnumSliceVarP(&options.ExcludeType, "exclude-type", "e", []goflags.EnumVariable{0}, "dns query type to exclude (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa)", queries),
	)

	flagSet.CreateGroup("filter", "过滤",
		flagSet.BoolVarP(&options.Response, "resp", "re", false, "display dns response"),
		flagSet.BoolVarP(&options.ResponseOnly, "resp-only", "ro", false, "display dns response only"),
		flagSet.StringVarP(&options.RCode, "rcode", "rc", "", "按DNS状态代码过滤结果（例如-rcode noerror，servfail，refused）"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVarP(&options.Threads, "threads", "t", 100, "number of concurrent threads to use"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", -1, "number of dns request/second to make (disabled as default)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVar(&options.OutputCDN, "cdn", false, "display cdn name"),
		flagSet.BoolVarP(&options.JSON, "json", "j", false, "write output in JSONL(ines) format"),
		flagSet.BoolVarP(&options.OmitRaw, "or", "omit-raw", false, "omit raw dns response from jsonl output"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "display only results in the output"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVarP(&options.Raw, "debug", "raw", false, "display raw dns response"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retry", 2, "number of dns attempts to make (must be at least 1)"),
		flagSet.BoolVar(&options.Trace, "trace", false, "perform dns tracing"),
		flagSet.IntVar(&options.TraceMaxRecursion, "trace-max-recursion", math.MaxInt16, "Max recursion for dns trace"),
		flagSet.BoolVar(&options.Stream, "stream", false, "stream mode (wordlist, wildcard, stats and stop/resume will be disabled)"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVarP(&options.Resolvers, "resolver", "r", "", "list of resolvers to use (file or comma separated)"),
		flagSet.IntVarP(&options.WildcardThreshold, "wildcard-threshold", "wt", 5, "wildcard filter threshold"),
		flagSet.StringVarP(&options.WildcardDomain, "wildcard-domain", "wd", "", "domain name for wildcard filtering (other flags will be ignored - only json output is supported)"),
	)

	_ = flagSet.Parse()

	options.configureQueryOptions()

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureRcodes()
	if err != nil {
		logx.Fatalf("%s", err)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.Response && options.ResponseOnly {
		logx.Warnf("resp and resp-only can't be used at the same time")
		return
	}

	if options.Retries == 0 {
		logx.Warnf("retries must be at least 1")
		return
	}

	wordListPresent := options.WordList != ""
	domainsPresent := options.Domains != ""

	if wordListPresent && !domainsPresent {
		logx.Warnf("missing domain(d) flag required with wordlist(w) input")
		return
	}

	// stdin can be set only on one flag
	if argumentHasStdin(options.Domains) && argumentHasStdin(options.WordList) {
		if options.Stream {
			logx.Warnf("argument stdin not supported in stream mode")
		}
		logx.Warnf("stdin can be set for one flag")
		return
	}

	if options.Stream {
		if wordListPresent {
			logx.Warnf("wordlist not supported in stream mode")
			return
		}
		if domainsPresent {
			logx.Warnf("domains not supported in stream mode")
			return
		}
		if options.WildcardDomain != "" {
			logx.Warnf("wildcard not supported in stream mode")
			return
		}
	}
}

func argumentHasStdin(arg string) bool {
	return arg == stdinMarker
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		logx.SetLevel("verbose")
	}
	if options.Silent {
		logx.SetLevel("silent")
	}
}

func (options *Options) configureRcodes() error {
	options.rcodes = make(map[int]struct{})
	rcodes := strings.Split(options.RCode, ",")
	for _, rcode := range rcodes {
		var rc int
		switch strings.ToLower(rcode) {
		case "":
			continue
		case "noerror":
			rc = 0
		case "formerr":
			rc = 1
		case "servfail":
			rc = 2
		case "nxdomain":
			rc = 3
		case "notimp":
			rc = 4
		case "refused":
			rc = 5
		case "yxdomain":
			rc = 6
		case "yxrrset":
			rc = 7
		case "nxrrset":
			rc = 8
		case "notauth":
			rc = 9
		case "notzone":
			rc = 10
		case "badsig", "badvers":
			rc = 16
		case "badkey":
			rc = 17
		case "badtime":
			rc = 18
		case "badmode":
			rc = 19
		case "badname":
			rc = 20
		case "badalg":
			rc = 21
		case "badtrunc":
			rc = 22
		case "badcookie":
			rc = 23
		default:
			var err error
			rc, err = strconv.Atoi(rcode)
			if err != nil {
				return errors.New("invalid rcode value")
			}
		}

		options.rcodes[rc] = struct{}{}
	}

	options.hasRCodes = options.RCode != ""
	return nil
}

func (options *Options) configureQueryOptions() {
	queryMap := map[string]*bool{
		"a":     &options.A,
		"aaaa":  &options.AAAA,
		"cname": &options.CNAME,
		"ns":    &options.NS,
		"txt":   &options.TXT,
		"srv":   &options.SRV,
		"ptr":   &options.PTR,
		"mx":    &options.MX,
		"soa":   &options.SOA,
		"axfr":  &options.AXFR,
		"caa":   &options.CAA,
		"any":   &options.ANY,
	}

	if options.QueryAll {
		for _, val := range queryMap {
			*val = true
		}
		options.Response = true
		// the ANY query type is not supported by the retryabledns library,
		// thus it's hard to filter the results when it's used in combination with other query types
		options.ExcludeType = append(options.ExcludeType, "any")
	}

	for _, et := range options.ExcludeType {
		if val, ok := queryMap[et]; ok {
			*val = false
		}
	}
}
