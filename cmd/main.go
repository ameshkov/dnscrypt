package main

import (
	"os"

	"github.com/AdguardTeam/golibs/log"

	goFlags "github.com/jessevdk/go-flags"
)

// Options - command-line options
type Options struct {
	Generate    GenerateArgs    `command:"generate" description:"Generates DNSCrypt server configuration"`
	LookupStamp LookupStampArgs `command:"lookup-stamp" description:"Performs a DNSCrypt lookup for the specified domain using an sdns:// stamp"`
	Lookup      LookupArgs      `command:"lookup" description:"Performs a DNSCrypt lookup for the specified domain"`
	Server      ServerArgs      `command:"server" description:"Runs a DNSCrypt resolver"`
	GenFromKeys GenFromKeysArgs `command:"gen-from-keys" description:"Generate DNSCrypt server configuration from .key files"`
	Version     struct {
	} `command:"version" description:"Prints version"`
}

// VersionString will be set through ldflags, contains current version
var VersionString = "1.0"

func main() {
	var opts Options

	var parser = goFlags.NewParser(&opts, goFlags.Default)
	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*goFlags.Error); ok && flagsErr.Type == goFlags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	switch parser.Active.Name {
	case "version":
		log.Printf("dnscrypt version %s\n", VersionString)
	case "generate":
		generate(opts.Generate)
	case "lookup-stamp":
		lookupStamp(opts.LookupStamp)
	case "lookup":
		lookup(opts.Lookup)
	case "server":
		server(opts.Server)
	case "gen-from-keys":
		genFromKeys(opts.GenFromKeys)
	default:
		log.Fatalf("unknown command %s", parser.Active.Name)
	}
}

