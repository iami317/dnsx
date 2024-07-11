package main

import (
	"github.com/iami317/dnsx"
	"github.com/iami317/logx"
)

func main() {
	options := dnsx.ParseOptions()
	options.OnResult = func(result *dnsx.Result) {
		logx.Infof("%s", result.String())
	}
	options.Domains = "github.com"
	dnsxRunner, err := dnsx.New(options)
	if err != nil {
		logx.Fatalf("Could not create runner: %s\n", err)
	}
	defer dnsxRunner.Close()

	err = dnsxRunner.Run()
	if err != nil {
		logx.Fatalf("%v", err)
	}
}
