package main

import (
	"crypto/ed25519"
	"io/ioutil"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
)

// ConvertWrapperArgs - "convert-dnscrypt-wrapper" command arguments
type ConvertWrapperArgs struct {
	PrivateKeyFile string `short:"p" long:"private-key" description:"DNSCrypt resolver private key file for certificate sign" required:"true"`
	ResolverSkFile string `short:"r" long:"resolver-sk-key" description:"Short-term private key file for encrypt/decrypt dns queries" required:"true"`
	ProviderName   string `short:"n" long:"provider-name" description:"DNSCrypt provider name" required:"true"`
	Out            string `short:"o" long:"out" description:"Path to the resulting config file" required:"true"`
	CertificateTTL int    `short:"t" long:"ttl" description:"Certificate time-to-live (seconds)"`
}

// convertWrapper - generates DNSCrypt configuration from both dnscrypt and server private keys
func convertWrapper(args ConvertWrapperArgs) {

	log.Info("Generating configuration for %s", args.ProviderName)

	var rc = dnscrypt.ResolverConfig{
		EsVersion:      dnscrypt.XSalsa20Poly1305,
		CertificateTTL: time.Duration(args.CertificateTTL) * time.Second,
		ProviderName:   args.ProviderName,
	}

	var privateKey ed25519.PrivateKey
	privateKey = getFileContent(args.PrivateKeyFile)
	if len(privateKey) != ed25519.PrivateKeySize {
		log.Fatal("Invalid private key.")
	}
	rc.PrivateKey = dnscrypt.HexEncodeKey(privateKey)
	rc.PublicKey = dnscrypt.HexEncodeKey(privateKey.Public().(ed25519.PublicKey))

	var resolverSecret ed25519.PrivateKey
	resolverSecret = getFileContent(args.ResolverSkFile)
	rc.ResolverSk = dnscrypt.HexEncodeKey(resolverSecret)
	rc.ResolverPk = dnscrypt.HexEncodeKey(getResolverPk(resolverSecret))

	out, err := yaml.Marshal(rc)
	if err != nil {
		log.Fatalf("Fail marshall output config, err: %s", err.Error())
	}

	err = ioutil.WriteFile(args.Out, out, 0666)
	if err != nil {
		log.Fatalf("Fail write file, err: %s", err.Error())
	}
}

// getResolverPk - generates public key corresponding to private
func getResolverPk(private ed25519.PrivateKey) ed25519.PublicKey {
	resolverSk := [32]byte{}
	resolverPk := [32]byte{}
	if len(private) != ed25519.PrivateKeySize {
		log.Fatal("Invalid resolver secret key.")
	}
	copy(resolverSk[:], private)
	curve25519.ScalarBaseMult(&resolverPk, &resolverSk)
	return resolverPk[:]
}

func getFileContent(fname string) []byte {
	bytes, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatalf("Fail read key file %s, err: %s", fname, err.Error())
	}
	return bytes
}
