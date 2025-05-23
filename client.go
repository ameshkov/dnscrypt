package dnscrypt

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// Client is a DNSCrypt resolver client
type Client struct {
	Net     string        // protocol (can be "udp" or "tcp", by default - "udp")
	Timeout time.Duration // read/write timeout

	// Logger is a logger instance for Client. If not set, slog.Default() will
	// be used.
	Logger *slog.Logger

	// UDPSize is the maximum size of a DNS response (or query) this client can
	// send or receive. If not set, we use dns.MinMsgSize by default.
	UDPSize int
}

// ResolverInfo contains DNSCrypt resolver information necessary for decryption/encryption
type ResolverInfo struct {
	SecretKey [keySize]byte // Client short-term secret key
	PublicKey [keySize]byte // Client short-term public key

	ServerPublicKey ed25519.PublicKey // Resolver public key (this key is used to validate cert signature)
	ServerAddress   string            // Server IP address
	ProviderName    string            // Provider name

	ResolverCert *Cert         // Certificate info (obtained with the first unencrypted DNS request)
	SharedKey    [keySize]byte // Shared key that is to be used to encrypt/decrypt messages
}

// Dial fetches and validates DNSCrypt certificate from the given server
// Data received during this call is then used for DNS requests encryption/decryption
// stampStr is an sdns:// address which is parsed using go-dnsstamps package
func (c *Client) Dial(stampStr string) (*ResolverInfo, error) {
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err != nil {
		// Invalid SDNS stamp
		return nil, err
	}

	if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return nil, ErrInvalidDNSStamp
	}

	return c.DialStamp(stamp)
}

// DialStamp fetches and validates DNSCrypt certificate from the given server
// Data received during this call is then used for DNS requests encryption/decryption
func (c *Client) DialStamp(stamp dnsstamps.ServerStamp) (*ResolverInfo, error) {
	resolverInfo := &ResolverInfo{}

	// Generate the secret/public pair
	resolverInfo.SecretKey, resolverInfo.PublicKey = generateRandomKeyPair()

	// Set the provider properties
	resolverInfo.ServerPublicKey = stamp.ServerPk
	resolverInfo.ServerAddress = stamp.ServerAddrStr
	resolverInfo.ProviderName = stamp.ProviderName

	cert, err := c.fetchCert(stamp)
	if err != nil {
		return nil, err
	}

	resolverInfo.ResolverCert = cert

	// Compute shared key that we'll use to encrypt/decrypt messages
	sharedKey, err := computeSharedKey(cert.EsVersion, &resolverInfo.SecretKey, &cert.ResolverPk)
	if err != nil {
		return nil, err
	}

	resolverInfo.SharedKey = sharedKey

	return resolverInfo, nil
}

// Exchange performs a synchronous DNS query to the specified DNSCrypt server and returns a DNS response.
// This method creates a new network connection for every call so avoid using it for TCP.
// DNSCrypt cert needs to be fetched and validated prior to this call using the c.DialStamp method.
func (c *Client) Exchange(m *dns.Msg, resolverInfo *ResolverInfo) (resp *dns.Msg, err error) {
	network := "udp"
	if c.Net == "tcp" {
		network = "tcp"
	}

	conn, err := net.Dial(network, resolverInfo.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("dialing: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, conn.Close()) }()

	resp, err = c.ExchangeConn(conn, m, resolverInfo)
	if err != nil {
		return nil, fmt.Errorf("exchanging: %w", err)
	}

	return resp, nil
}

// ExchangeConn performs a synchronous DNS query to the specified DNSCrypt server and returns a DNS response.
// DNSCrypt server information needs to be fetched and validated prior to this call using the c.DialStamp method
func (c *Client) ExchangeConn(conn net.Conn, m *dns.Msg, resolverInfo *ResolverInfo) (*dns.Msg, error) {
	query, err := c.encrypt(m, resolverInfo)
	if err != nil {
		return nil, err
	}

	err = c.writeQuery(conn, query)
	if err != nil {
		return nil, err
	}

	b, err := c.readResponse(conn)
	if err != nil {
		return nil, err
	}

	res, err := c.decrypt(b, resolverInfo)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// writeQuery writes query to the network connection
// depending on the protocol we may write a 2-byte prefix or not
func (c *Client) writeQuery(conn net.Conn, query []byte) error {
	var err error

	if c.Timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	}

	// Write to the connection
	if _, ok := conn.(*net.TCPConn); ok {
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(query)))
		_, err = (&net.Buffers{l, query}).WriteTo(conn)
	} else {
		_, err = conn.Write(query)
	}

	return err
}

// readResponse reads response from the network connection
// depending on the protocol, we may read a 2-byte prefix or not
func (c *Client) readResponse(conn net.Conn) ([]byte, error) {
	if c.Timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(c.Timeout))
	}

	proto := "udp"
	if _, ok := conn.(*net.TCPConn); ok {
		proto = "tcp"
	}

	if proto == "udp" {
		bufSize := c.UDPSize
		if bufSize == 0 {
			bufSize = dns.MinMsgSize
		}
		response := make([]byte, bufSize)
		n, err := conn.Read(response)
		if err != nil {
			return nil, err
		}
		return response[:n], nil
	}

	// If we got here, this is a TCP connection
	// so we should read a 2-byte prefix first
	return readPrefixed(conn)
}

// encrypt encrypts a DNS message using shared key from the resolver info
func (c *Client) encrypt(m *dns.Msg, resolverInfo *ResolverInfo) ([]byte, error) {
	q := EncryptedQuery{
		EsVersion:   resolverInfo.ResolverCert.EsVersion,
		ClientMagic: resolverInfo.ResolverCert.ClientMagic,
		ClientPk:    resolverInfo.PublicKey,
	}
	query, err := m.Pack()
	if err != nil {
		return nil, err
	}
	b, err := q.Encrypt(query, resolverInfo.SharedKey)
	if len(b) > c.maxQuerySize() {
		return nil, ErrQueryTooLarge
	}

	return b, err
}

// decrypts decrypts a DNS message using a shared key from the resolver info
func (c *Client) decrypt(b []byte, resolverInfo *ResolverInfo) (*dns.Msg, error) {
	dr := EncryptedResponse{
		EsVersion: resolverInfo.ResolverCert.EsVersion,
	}
	msg, err := dr.Decrypt(b, resolverInfo.SharedKey)
	if err != nil {
		return nil, err
	}

	res := new(dns.Msg)
	err = res.Unpack(msg)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// fetchCert loads DNSCrypt cert from the specified server
func (c *Client) fetchCert(stamp dnsstamps.ServerStamp) (cert *Cert, err error) {
	providerName := stamp.ProviderName
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}

	query := new(dns.Msg)
	query.SetQuestion(providerName, dns.TypeTXT)
	// use 1252 as a UDPSize for this client to make sure the buffer is not too small
	client := dns.Client{Net: c.Net, UDPSize: uint16(1252), Timeout: c.Timeout}
	r, _, err := client.Exchange(query, stamp.ServerAddrStr)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, ErrFailedToFetchCert
	}

	currentCert := &Cert{}
	foundValid := false
	for _, rr := range r.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}

		cert, err = c.parseCert(stamp, currentCert, providerName, strings.Join(txt.Txt, ""))
		if err != nil {
			c.logger().Debug("bad cert", "provider", providerName, slogutil.KeyError, err)

			continue
		} else if cert == nil {
			// The certificate has been skipped due to Serial or EsVersion.
			continue
		}

		currentCert = cert
		foundValid = true
	}

	if foundValid {
		return currentCert, nil
	} else if err == nil {
		err = fmt.Errorf("no valid txt records for provider %q", providerName)
	}

	return nil, err
}

// parseCert parses a certificate from its string form and returns it if it has
// priority over currentCert.
func (c *Client) parseCert(
	stamp dnsstamps.ServerStamp,
	currentCert *Cert,
	providerName string,
	certStr string,
) (cert *Cert, err error) {
	certBytes, err := unpackTxtString(certStr)
	if err != nil {
		return nil, fmt.Errorf("unpacking txt record: %w", err)
	}

	cert = &Cert{}
	err = cert.Deserialize(certBytes)
	if err != nil {
		return nil, fmt.Errorf("deserializing cert for: %w", err)
	}

	c.logger().Debug(
		"fetched certificate",
		"provider",
		providerName,
		"cert_serial",
		cert.Serial,
	)

	if !cert.VerifyDate() {
		return nil, ErrInvalidDate
	}

	if !cert.VerifySignature(stamp.ServerPk) {
		return nil, ErrInvalidCertSignature
	}

	if cert.Serial < currentCert.Serial {
		c.logger().Debug(
			"cert superseded by a previous certificate",
			"provider",
			providerName,
			"cert_serial",
			cert.Serial,
		)

		return nil, nil
	}

	if cert.Serial > currentCert.Serial {
		return cert, nil
	}

	if cert.EsVersion <= currentCert.EsVersion {
		c.logger().Debug(
			"keeping the current cert es version",
			"provider",
			providerName,
		)

		return nil, nil
	}

	c.logger().Debug(
		"upgrading the construction",
		"provider",
		providerName,
		"es_version",
		currentCert.EsVersion,
		"new_es_version",
		cert.EsVersion,
	)

	return cert, nil
}

func (c *Client) maxQuerySize() int {
	if c.Net == "tcp" {
		return dns.MaxMsgSize
	}

	if c.UDPSize > 0 {
		return c.UDPSize
	}

	return dns.MinMsgSize
}

func (c *Client) logger() (l *slog.Logger) {
	if c.Logger == nil {
		return slog.Default()
	}

	return c.Logger
}
