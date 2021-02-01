package main

import (
	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"time"
)

// GenerateArgs - "generate" command arguments
type GenFromKeysArgs struct {
	DNSCryptKeyFile string `short:"d" long:"crypt-key" description:"DNSCryptResolver private key filename" required:"true"`
	ServerKeyFile   string `short:"s" long:"server-key" description:"Server private key filename" required:"true"`
	ProviderName    string `short:"p" long:"provider-name" description:"DNSCrypt provider name" required:"true"`
	Out             string `short:"o" long:"out" description:"Path to the resulting config file" required:"true"`
	CertificateTTL  int    `short:"t" long:"ttl" description:"Certificate time-to-live (seconds)"`
}

// genFromKeys - generates DNSCrypt configuration from both dnscrypt and server private keys
func genFromKeys(args GenFromKeysArgs) {
	var rc = dnscrypt.ResolverConfig{
		EsVersion:      dnscrypt.XSalsa20Poly1305,
		CertificateTTL: time.Duration(args.CertificateTTL) * time.Second,
		ProviderName:   args.ProviderName,
	}

	log.Info("Generating configuration for %s", args.ProviderName)

	privateCrypt := getFileContent(args.DNSCryptKeyFile)
	rc.PrivateKey = dnscrypt.HexEncodeKey(privateCrypt)
	rc.PublicKey = dnscrypt.HexEncodeKey(privateCrypt[len(privateCrypt)/2:])

	privateServer := getFileContent(args.ServerKeyFile)
	rc.ResolverSk = dnscrypt.HexEncodeKey(privateServer)
	rc.ResolverPk = dnscrypt.HexEncodeKey(privateCrypt[len(privateServer)/2:])

	out, err := yaml.Marshal(rc)
	if err != nil {
		log.Fatalf("Fail marshall output config, err: %s", err.Error())
	}

	err = ioutil.WriteFile(args.Out, out, 0666)
	if err != nil {
		log.Fatalf("Fail write file, err: %s", err.Error())
	}
}

func getFileContent(fname string) []byte {
	bytes, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatalf("Fail read key file %s, err: %s", fname, err.Error())
	}
	return bytes
}
