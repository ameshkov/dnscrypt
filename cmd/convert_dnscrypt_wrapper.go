package main

import (
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
)

// ConvertWrapperArgs - "convert-dnscrypt-wrapper" command arguments
type ConvertWrapperArgs struct {
	PrivateKeyFile string `short:"p" long:"private-key" description:"Path to the DNSCrypt resolver private key file that is used for signing certificates. Param is required." required:"true"`
	ResolverSkFile string `short:"r" long:"resolver-secret" description:"Path to the Short-term privacy key file for encrypting/decrypting DNS queries. If not specified, resolver_secret and resolver_public will be randomly generated."`
	ProviderName   string `short:"n" long:"provider-name" description:"DNSCrypt provider name. Param is required." required:"true"`
	Out            string `short:"o" long:"out" description:"Path to the resulting config file. Param is required." required:"true"`
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

	// make PrivateKey
	var privateKey ed25519.PrivateKey
	privateKey = getFileContent(args.PrivateKeyFile)
	if len(privateKey) != ed25519.PrivateKeySize {
		log.Fatal("Invalid private key.")
	}
	rc.PrivateKey = dnscrypt.HexEncodeKey(privateKey)

	// make PublicKey
	publicKey := privateKey.Public().(ed25519.PublicKey)
	rc.PublicKey = dnscrypt.HexEncodeKey(publicKey)

	// make ResolverSk
	var resolverSecret ed25519.PrivateKey
	resolverSecret = getFileContent(args.ResolverSkFile)
	if len(resolverSecret) != 32 {
		log.Fatal("Invalid resolver secret key.")
	}
	rc.ResolverSk = dnscrypt.HexEncodeKey(resolverSecret)

	// make ResolverPk
	resolverPublic := getResolverPk(resolverSecret)
	rc.ResolverPk = dnscrypt.HexEncodeKey(resolverPublic)

	if err := validateRc(rc, publicKey); err != nil {
		log.Fatalf("Failed to validate resolver config, err: %s", err.Error())
	}

	out, err := yaml.Marshal(rc)
	if err != nil {
		log.Fatalf("Failed to marshall output config, err: %s", err.Error())
	}

	err = ioutil.WriteFile(args.Out, out, 0600)
	if err != nil {
		log.Fatalf("Failed to write file, err: %s", err.Error())
	}
}

// validateRc - verifies that the certificate is correctly
// created and validated for this resolver config. if rc valid returns nil.
func validateRc(rc dnscrypt.ResolverConfig, publicKey ed25519.PublicKey) error {
	cert, err := rc.CreateCert()
	if err != nil {
		return fmt.Errorf("failed to validate cert, err: %s", err.Error())
	}
	if cert == nil {
		return fmt.Errorf("created cert is empty")
	}
	if !cert.VerifyDate() {
		return fmt.Errorf("cert date is not valid")
	}
	if !cert.VerifySignature(publicKey) {
		return fmt.Errorf("cert signed incorrectly")
	}
	return nil
}

// getResolverPk - calculates public key from private key
func getResolverPk(private ed25519.PrivateKey) ed25519.PublicKey {
	resolverSk := [32]byte{}
	resolverPk := [32]byte{}
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
