package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// LookupStampArgs is the "lookup-stamp" command arguments structure
type LookupStampArgs struct {
	Network string `short:"n" long:"network" description:"network type (tcp/udp)" default:"udp"`
	Stamp   string `short:"s" long:"stamp" description:"DNSCrypt resolver stamp. Param is required." required:"true"`
	Domain  string `short:"d" long:"domain" description:"Domain to resolve. Param is required." required:"true"`
	Type    string `short:"t" long:"type" description:"DNS query type" default:"A"`
}

// LookupArgs is the "lookup" command arguments structure
type LookupArgs struct {
	Network      string `short:"n" long:"network" description:"network type (tcp/udp)" default:"udp"`
	ProviderName string `short:"p" long:"provider-name" description:"DNSCrypt resolver provider name. Param is required." required:"true"`
	PublicKey    string `short:"k" long:"public-key" description:"DNSCrypt resolver public key. Param is required." required:"true"`
	ServerAddr   string `short:"a" long:"addr" description:"Resolver address (IP[:port]). By default, the port is 443. Param is required." required:"true"`
	Domain       string `short:"d" long:"domain" description:"Domain to resolve. Param is required." required:"true"`
	Type         string `short:"t" long:"type" description:"DNS query type" default:"A"`
}

// LookupResult is the lookup result that contains the cert info and the query response
type LookupResult struct {
	Certificate struct {
		Serial    uint32    `json:"serial"`
		EsVersion string    `json:"encryption"`
		NotAfter  time.Time `json:"not_after"`
		NotBefore time.Time `json:"not_before"`
	} `json:"certificate"`

	Reply *dns.Msg `json:"reply"`
}

// lookup performs a DNS lookup, prints DNSCrypt info and lookup results
func lookup(args LookupArgs) {
	serverPk, err := dnscrypt.HexDecodeKey(args.PublicKey)
	if err != nil {
		log.Fatalf("invalid resolver public key: %v", err)
	}

	stamp := dnsstamps.ServerStamp{
		ProviderName:  args.ProviderName,
		ServerPk:      serverPk,
		ServerAddrStr: args.ServerAddr,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}

	lookupStamp(LookupStampArgs{
		Network: args.Network,
		Stamp:   stamp.String(),
		Domain:  args.Domain,
		Type:    args.Type,
	})
}

// lookupStamp performs a DNS lookup, prints DNSCrypt cert info and lookup results
func lookupStamp(args LookupStampArgs) {
	c := &dnscrypt.Client{
		Net:     args.Network,
		Timeout: 10 * time.Second,
	}
	ri, err := c.Dial(args.Stamp)

	if err != nil {
		log.Fatalf("failed to establish connection with the server: %v", err)
	}

	res := LookupResult{}
	res.Certificate.Serial = ri.ResolverCert.Serial
	res.Certificate.NotAfter = time.Unix(int64(ri.ResolverCert.NotAfter), 0)
	res.Certificate.NotBefore = time.Unix(int64(ri.ResolverCert.NotBefore), 0)
	res.Certificate.EsVersion = ri.ResolverCert.EsVersion.String()

	dnsType, ok := dns.StringToType[strings.ToUpper(args.Type)]
	if !ok {
		log.Fatalf("invalid type %s", args.Type)
	}

	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{
			Name:   dns.Fqdn(args.Domain),
			Qtype:  dnsType,
			Qclass: dns.ClassINET,
		},
	}

	reply, err := c.Exchange(req, ri)
	if err != nil {
		log.Fatalf("failed to resolve %s %s", args.Type, args.Domain)
	}

	res.Reply = reply
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal result to json: %v", err)
	}

	_, _ = os.Stdout.WriteString(string(b) + "\n")
}
