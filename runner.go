package dnsx

import (
	"bufio"
	"context"
	"fmt"
	"github.com/iami317/dnsx/dicts"
	"github.com/iami317/dnsx/libs"
	"github.com/iami317/logx"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryabledns"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	options             *Options
	dnsx                *libs.DNSX
	wgOutPutWorker      *sync.WaitGroup
	wgResolveWorkers    *sync.WaitGroup
	wgWildCardWorker    *sync.WaitGroup
	workerChan          chan string
	outputChan          chan string
	wildCardWorkerChan  chan string
	wildcards           map[string]struct{}
	wildCardsMutex      sync.RWMutex
	wildCardsCache      map[string][]string
	wildCardsCacheMutex sync.Mutex
	limiter             *ratelimit.Limiter
	hm                  *hybrid.HybridMap
	tmpStdinFile        string
	aurora              aurora.Aurora
}

type ResultFn func(result *Result)

type Result struct {
	Domain       string `json:"domain"`
	Items        string `json:"items"`
	QueryType    string `json:"query_type"`
	ResponseCode string `json:"response_code,omitempty"`
	CdnName      string `json:"cdn_name,omitempty"`
	Asn          string `json:"asn,omitempty"`
}

func (re *Result) String() string {
	return fmt.Sprintf(
		"domain:%v -- items:%v -- query_type:%v -- response_code:%v -- cdn_name:%v -- asn:%v",
		re.Domain,
		re.Items,
		re.QueryType,
		re.ResponseCode,
		re.CdnName,
		re.Asn,
	)
}

func New(options *Options) (*Runner, error) {
	retryabledns.CheckInternalIPs = true

	dnsxOptions := libs.DefaultOptions
	dnsxOptions.MaxRetries = options.Retries
	dnsxOptions.TraceMaxRecursion = options.TraceMaxRecursion
	dnsxOptions.OutputCDN = options.OutputCDN
	if options.Resolvers != "" {
		dnsxOptions.BaseResolvers = []string{}
		// If it's a file load resolvers from it
		if fileutil.FileExists(options.Resolvers) {
			rs, err := linesInFile(options.Resolvers)
			if err != nil {
				logx.Fatalf("%s\n", err)
			}
			for _, rr := range rs {
				dnsxOptions.BaseResolvers = append(dnsxOptions.BaseResolvers, prepareResolver(rr))
			}
		} else {
			// otherwise gets comma separated ones
			for _, rr := range strings.Split(options.Resolvers, ",") {
				dnsxOptions.BaseResolvers = append(dnsxOptions.BaseResolvers, prepareResolver(rr))
			}
		}
	}

	var questionTypes []uint16
	if options.A {
		questionTypes = append(questionTypes, dns.TypeA)
	}
	if options.AAAA {
		questionTypes = append(questionTypes, dns.TypeAAAA)
	}
	if options.CNAME {
		questionTypes = append(questionTypes, dns.TypeCNAME)
	}
	if options.PTR {
		questionTypes = append(questionTypes, dns.TypePTR)
	}
	if options.SOA {
		questionTypes = append(questionTypes, dns.TypeSOA)
	}
	if options.ANY {
		questionTypes = append(questionTypes, dns.TypeANY)
	}
	if options.TXT {
		questionTypes = append(questionTypes, dns.TypeTXT)
	}
	if options.SRV {
		questionTypes = append(questionTypes, dns.TypeSRV)
	}
	if options.MX {
		questionTypes = append(questionTypes, dns.TypeMX)
	}
	if options.NS {
		questionTypes = append(questionTypes, dns.TypeNS)
	}
	if options.CAA {
		questionTypes = append(questionTypes, dns.TypeCAA)
	}

	// If no option is specified or wildcard filter has been requested use query type A
	if len(questionTypes) == 0 || options.WildcardDomain != "" {
		options.A = true
		questionTypes = append(questionTypes, dns.TypeA)
	}
	dnsxOptions.QuestionTypes = questionTypes
	dnsxOptions.QueryAll = options.QueryAll

	dnsX, err := libs.NewDnsx(dnsxOptions)
	if err != nil {
		return nil, err
	}

	limiter := ratelimit.NewUnlimited(context.Background())
	if options.RateLimit > 0 {
		limiter = ratelimit.New(context.Background(), uint(options.RateLimit), time.Second)
	}

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}

	r := Runner{
		options:            options,
		dnsx:               dnsX,
		wgOutPutWorker:     &sync.WaitGroup{},
		wgResolveWorkers:   &sync.WaitGroup{},
		wgWildCardWorker:   &sync.WaitGroup{},
		workerChan:         make(chan string),
		wildCardWorkerChan: make(chan string),
		wildcards:          make(map[string]struct{}),
		wildCardsCache:     make(map[string][]string),
		limiter:            limiter,
		hm:                 hm,
		//stats:              stats,
		aurora: aurora.NewAurora(true),
	}

	return &r, nil
}

func (r *Runner) InputWorkerStream() {
	var sc *bufio.Scanner
	// attempt to load list from file
	if fileutil.HasStdin() {
		sc = bufio.NewScanner(os.Stdin)
	}

	for sc.Scan() {
		item := strings.TrimSpace(sc.Text())
		switch {
		case iputil.IsCIDR(item):
			hostsC, _ := mapcidr.IPAddressesAsStream(item)
			for host := range hostsC {
				r.workerChan <- host
			}
		case asn.IsASN(item):
			hostsC, _ := asn.GetIPAddressesAsStream(item)
			for host := range hostsC {
				r.workerChan <- host
			}
		default:
			r.workerChan <- item
		}
	}
	close(r.workerChan)
}

func (r *Runner) InputWorker() {
	r.hm.Scan(func(k, _ []byte) error {
		item := string(k)
		r.workerChan <- item
		return nil
	})
	close(r.workerChan)
}

func (r *Runner) prepareInput() error {
	var (
		dataDomains chan string
		sc          chan string
		err         error
	)

	// copy stdin to a temporary file
	hasStdin := fileutil.HasStdin()
	if hasStdin {
		tmpStdinFile, err := fileutil.GetTempFileName()
		if err != nil {
			return err
		}
		r.tmpStdinFile = tmpStdinFile

		stdinFile, err := os.Create(r.tmpStdinFile)
		if err != nil {
			return err
		}
		if _, err := io.Copy(stdinFile, os.Stdin); err != nil {
			return err
		}
		// closes the file as we will read it multiple times to build the iterations
		stdinFile.Close()
		defer os.RemoveAll(r.tmpStdinFile)
	}

	if r.options.Domains != "" {
		dataDomains, err = r.preProcessArgument(r.options.Domains)
		if err != nil {
			return err
		}
		sc = dataDomains
	}

	if sc == nil {
		if hasStdin {
			sc, err = fileutil.ReadFile(r.tmpStdinFile)
			if err != nil {
				return err
			}
		} else {
			return errors.New("hosts file or stdin not provided")
		}
	}

	numHosts := 0
	for item := range sc {
		item := normalize(item)
		var hosts []string
		switch {
		case strings.Contains(item, "FUZZ"):
			fuzz, err := r.preProcessArgument(r.options.WordList)
			if err != nil {
				return err
			}
			for r := range fuzz {
				subdomain := strings.ReplaceAll(item, "FUZZ", r)
				hosts = append(hosts, subdomain)
			}
			numHosts += r.addHostsToHMapFromList(hosts)
		case r.options.WordList != "":
			// prepare wordlist
			prefixes, err := r.preProcessArgument(r.options.WordList)
			if err != nil {
				return err
			}
			for prefix := range prefixes {
				// domains Cartesian product with wordlist
				subdomain := strings.TrimSpace(prefix) + "." + item
				hosts = append(hosts, subdomain)
			}
			numHosts += r.addHostsToHMapFromList(hosts)
		case r.options.WordList == "":
			s, _ := dicts.FSString(false, "/wordlists.txt")
			prefixes := strings.Split(s, "\n")
			for _, prefix := range prefixes {
				subdomain := strings.TrimSpace(prefix) + "." + item
				hosts = append(hosts, subdomain)
			}
			numHosts += r.addHostsToHMapFromList(hosts)
		case iputil.IsCIDR(item):
			hostC, err := mapcidr.IPAddressesAsStream(item)
			if err != nil {
				return err
			}
			numHosts += r.addHostsToHMapFromChan(hostC)
		case asn.IsASN(item):
			hostC, err := asn.GetIPAddressesAsStream(item)
			if err != nil {
				return err
			}
			numHosts += r.addHostsToHMapFromChan(hostC)
		default:
			hosts = []string{item}
			numHosts += r.addHostsToHMapFromList(hosts)
		}
	}

	return nil
}

func (r *Runner) addHostsToHMapFromList(hosts []string) (numHosts int) {
	for _, host := range hosts {
		// Used just to get the exact number of targets
		if _, ok := r.hm.Get(host); ok {
			continue
		}
		numHosts++
		// nolint:errcheck
		r.hm.Set(host, nil)
	}
	return
}

func (r *Runner) addHostsToHMapFromChan(hosts chan string) (numHosts int) {
	for host := range hosts {
		// Used just to get the exact number of targets
		if _, ok := r.hm.Get(host); ok {
			continue
		}
		numHosts++
		// nolint:errcheck
		r.hm.Set(host, nil)
	}
	return
}

func (r *Runner) preProcessArgument(arg string) (chan string, error) {
	// read from:
	// file
	switch {
	case fileutil.FileExists(arg):
		return fileutil.ReadFile(arg)
	// stdin
	case argumentHasStdin(arg):
		return fileutil.ReadFile(r.tmpStdinFile)
	// inline
	case arg != "":
		data := strings.ReplaceAll(arg, Comma, NewLine)
		return fileutil.ReadFileWithReader(strings.NewReader(data))
	default:
		return nil, errors.New("empty argument")
	}
}

func normalize(data string) string {
	return strings.TrimSpace(data)
}

func (r *Runner) Run() error {
	if r.options.Stream {
		return r.runStream()
	}

	return r.run()
}

func (r *Runner) run() error {
	err := r.prepareInput()
	if err != nil {
		return err
	}

	r.startWorkers()

	r.wgResolveWorkers.Wait()

	close(r.outputChan)
	r.wgOutPutWorker.Wait()
	if r.options.WildcardDomain != "" {
		logx.Println("Starting to filter wildcard subdomains")
		ipDomain := make(map[string]map[string]struct{})
		listIPs := []string{}
		// prepare in memory structure similarly to shuffledns
		r.hm.Scan(func(k, v []byte) error {
			var dnsdata retryabledns.DNSData
			err := dnsdata.Unmarshal(v)
			if err != nil {
				// the item has no record - ignore
				return nil
			}

			for _, a := range dnsdata.A {
				_, ok := ipDomain[a]
				if !ok {
					ipDomain[a] = make(map[string]struct{})
					listIPs = append(listIPs, a)
				}
				ipDomain[a][string(k)] = struct{}{}
			}

			return nil
		})

		// wildcard workers
		numThreads := r.options.Threads
		if numThreads > len(listIPs) {
			numThreads = len(listIPs)
		}
		for i := 0; i < numThreads; i++ {
			r.wgWildCardWorker.Add(1)
			go r.wildcardWorker()
		}

		seen := make(map[string]struct{})
		for _, a := range listIPs {
			hosts := ipDomain[a]
			if len(hosts) >= r.options.WildcardThreshold {
				for host := range hosts {
					if _, ok := seen[host]; !ok {
						seen[host] = struct{}{}
						r.wildCardWorkerChan <- host
					}
				}
			}
		}
		close(r.wildCardWorkerChan)
		r.wgWildCardWorker.Wait()

		// we need to restart output
		r.startOutputWorker()
		seen = make(map[string]struct{})
		seenRemovedSubdomains := make(map[string]struct{})
		numRemovedSubdomains := 0
		for _, A := range listIPs {
			for host := range ipDomain[A] {
				if host == r.options.WildcardDomain {
					if _, ok := seen[host]; !ok {
						seen[host] = struct{}{}
						_ = r.lookupAndOutput(host)
					}
				} else if _, ok := r.wildcards[host]; !ok {
					if _, ok := seen[host]; !ok {
						seen[host] = struct{}{}
						_ = r.lookupAndOutput(host)
					}
				} else {
					if _, ok := seenRemovedSubdomains[host]; !ok {
						numRemovedSubdomains++
						seenRemovedSubdomains[host] = struct{}{}
					}
				}
			}
		}
		close(r.outputChan)
		r.wgOutPutWorker.Wait()
		logx.Println(fmt.Sprintf("%d wildcard subdomains removed", numRemovedSubdomains))
	}

	return nil
}

func (r *Runner) lookupAndOutput(host string) error {
	if r.options.JSON {
		if data, ok := r.hm.Get(host); ok {
			var dnsData retryabledns.DNSData
			err := dnsData.Unmarshal(data)
			if err != nil {
				return err
			}
			dnsDataJson, err := dnsData.JSON()
			if err != nil {
				return err
			}
			r.outputChan <- dnsDataJson
			return err
		}
	}

	r.outputChan <- host
	return nil
}

func (r *Runner) runStream() error {
	r.startWorkers()

	r.wgResolveWorkers.Wait()

	close(r.outputChan)
	r.wgOutPutWorker.Wait()

	return nil
}

func (r *Runner) HandleOutput() {
	defer r.wgOutPutWorker.Done()

	for item := range r.outputChan {
		// writes sequentially to stdout
		logx.Silentf("--%s", item)
	}
}

func (r *Runner) startOutputWorker() {
	// output worker
	r.outputChan = make(chan string)
	r.wgOutPutWorker.Add(1)
	go r.HandleOutput()
}

func (r *Runner) startWorkers() {
	if r.options.Stream {
		go r.InputWorkerStream()
	} else {
		go r.InputWorker()
	}

	r.startOutputWorker()
	// resolve workers
	for i := 0; i < r.options.Threads; i++ {
		r.wgResolveWorkers.Add(1)
		go r.worker()
	}
}

func (r *Runner) worker() {
	defer r.wgResolveWorkers.Done()
	for domain := range r.workerChan {
		if isURL(domain) {
			domain = extractDomain(domain)
		}
		r.limiter.Take()
		dnsData := libs.ResponseData{}
		// Ignoring errors as partial results are still good
		dnsData.DNSData, _ = r.dnsx.QueryMultiple(domain)
		// Just skipping nil responses (in case of critical errors)
		if dnsData.DNSData == nil {
			continue
		}

		if dnsData.Host == "" || dnsData.Timestamp.IsZero() {
			continue
		}

		// results from hosts file are always returned
		if !dnsData.HostsFile {
			// skip responses not having the expected response code
			if len(r.options.rcodes) > 0 {
				if _, ok := r.options.rcodes[dnsData.StatusCodeRaw]; !ok {
					continue
				}
			}
		}

		if !r.options.Raw {
			dnsData.Raw = ""
		}

		if r.options.Trace {
			dnsData.TraceData, _ = r.dnsx.Trace(domain)
			if dnsData.TraceData != nil {
				for _, data := range dnsData.TraceData.DNSData {
					if r.options.Raw && data.RawResp != nil {
						rawRespString := data.RawResp.String()
						data.Raw = rawRespString
						// join the whole chain in raw field
						dnsData.Raw += fmt.Sprintln(rawRespString)
					}
					data.RawResp = nil
				}
			}
		}

		if r.options.AXFR {
			hasAxfrData := false
			axfrData, _ := r.dnsx.AXFR(domain)
			if axfrData != nil {
				dnsData.AXFRData = axfrData
				hasAxfrData = len(axfrData.DNSData) > 0
			}

			// if the query type is only AFXR then output only if we have results (ref: https://github.com/projectdiscovery/dnsx/issues/230#issuecomment-1256659249)
			if len(r.dnsx.Options.QuestionTypes) == 1 && !hasAxfrData && !r.options.JSON {
				continue
			}
		}
		// add flags for cdn
		if r.options.OutputCDN {
			dnsData.IsCDNIP, dnsData.CDNName, _ = r.dnsx.CdnCheck(domain)
		}

		// if wildcard filtering just store the data
		if r.options.WildcardDomain != "" {
			_ = r.storeDNSData(dnsData.DNSData)
			continue
		}
		if r.options.JSON {
			var marshalOptions []libs.MarshalOption
			if r.options.OmitRaw {
				marshalOptions = append(marshalOptions, libs.WithoutAllRecords())
			}
			jsons, _ := dnsData.JSON(marshalOptions...)
			r.outputChan <- jsons
			continue
		}
		if r.options.Raw {
			r.outputChan <- dnsData.Raw
			continue
		}
		if r.options.hasRCodes {
			r.outputResponseCode(domain, dnsData.StatusCodeRaw)
			continue
		}
		if r.options.A {
			r.outputRecordType(domain, dnsData.A, "A", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.AAAA {
			r.outputRecordType(domain, dnsData.AAAA, "AAAA", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.CNAME {
			r.outputRecordType(domain, dnsData.CNAME, "CNAME", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.PTR {
			r.outputRecordType(domain, dnsData.PTR, "PTR", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.MX {
			r.outputRecordType(domain, dnsData.MX, "MX", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.NS {
			r.outputRecordType(domain, dnsData.NS, "NS", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.SOA {
			r.outputRecordType(domain, sliceutil.Dedupe(dnsData.GetSOARecords()), "SOA", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.ANY {
			allParsedRecords := sliceutil.Merge(
				dnsData.A,
				dnsData.AAAA,
				dnsData.CNAME,
				dnsData.MX,
				dnsData.PTR,
				sliceutil.Dedupe(dnsData.GetSOARecords()),
				dnsData.NS,
				dnsData.TXT,
				dnsData.SRV,
				dnsData.CAA,
			)
			r.outputRecordType(domain, allParsedRecords, "ANY", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.TXT {
			r.outputRecordType(domain, dnsData.TXT, "TXT", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.SRV {
			r.outputRecordType(domain, dnsData.SRV, "SRV", dnsData.CDNName, dnsData.ASN, dnsData)
		}
		if r.options.CAA {
			r.outputRecordType(domain, dnsData.CAA, "CAA", dnsData.CDNName, dnsData.ASN, dnsData)
		}
	}
}

func (r *Runner) outputRecordType(domain string, items interface{}, queryType, cdnName string, asn *libs.AsnResponse, dnsData libs.ResponseData) {
	var details string
	if cdnName != "" {
		details = fmt.Sprintf(" [%s]", cdnName)
	}
	if asn != nil {
		details = fmt.Sprintf("%s %s", details, asn.String())
	}
	var records []string

	switch items := items.(type) {
	case []string:
		records = items
	case []retryabledns.SOA:
		for _, item := range items {
			records = append(records, item.NS, item.Mbox)
		}
	}

	for _, item := range records {
		item := strings.ToLower(item)
		if r.options.OnResult != nil {
			result := &Result{
				Domain:    domain,
				QueryType: queryType,
				Items:     item,
				CdnName:   cdnName,
			}
			if asn != nil {
				result.Asn = asn.String()
			}
			responseCodeExt, ok := dns.RcodeToString[dnsData.StatusCodeRaw]
			if ok {
				result.ResponseCode = responseCodeExt
			}
			r.options.OnResult(result)
		} else if r.options.ResponseOnly {
			r.outputChan <- fmt.Sprintf("%s%s", item, details)
		} else if r.options.Response {
			r.outputChan <- fmt.Sprintf("%s [%s] [%s] %s", domain, r.aurora.Magenta(queryType), r.aurora.Green(item).String(), details)
		} else {
			// just prints out the domain if it has a record type and exit
			r.outputChan <- fmt.Sprintf("%s%s", domain, details)
			break
		}
	}
}

func (r *Runner) outputResponseCode(domain string, responsecode int) {
	responseCodeExt, ok := dns.RcodeToString[responsecode]
	if ok {
		r.outputChan <- domain + " [" + responseCodeExt + "]"
	}
}

func (r *Runner) storeDNSData(dnsdata *retryabledns.DNSData) error {
	data, err := dnsdata.Marshal()
	if err != nil {
		return err
	}
	return r.hm.Set(dnsdata.Host, data)
}

// Close running instance
func (r *Runner) Close() {
	r.hm.Close()
}

func (r *Runner) wildcardWorker() {
	defer r.wgWildCardWorker.Done()

	for {
		host, more := <-r.wildCardWorkerChan
		if !more {
			break
		}

		if r.IsWildcard(host) {
			// mark this host as a wildcard subdomain
			r.wildCardsMutex.Lock()
			r.wildcards[host] = struct{}{}
			r.wildCardsMutex.Unlock()
		}
	}
}
