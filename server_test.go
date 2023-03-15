package dnscrypt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestServer_Shutdown(t *testing.T) {
	n := runtime.GOMAXPROCS(1)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(n)
	})
	srv := newTestServer(t, &testHandler{})
	// Serve* methods are called in different goroutines
	// give them at least a moment to actually start the server
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, srv.Close())
}

func TestServer_UDPServeCert(t *testing.T) {
	testServerServeCert(t, "udp")
}

func TestServer_TCPServeCert(t *testing.T) {
	testServerServeCert(t, "tcp")
}

func TestServer_UDPRespondMessages(t *testing.T) {
	testServerRespondMessages(t, "udp")
}

func TestServer_TCPRespondMessages(t *testing.T) {
	testServerRespondMessages(t, "tcp")
}

func TestServer_ReadTimeout(t *testing.T) {
	srv := newTestServer(t, &testHandler{})
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})
	// Sleep for "defaultReadTimeout" before trying to shutdown the server
	// The point is to make sure readTimeout is properly handled by
	// the "Serve*" goroutines and they don't finish their work unexpectedly
	time.Sleep(defaultReadTimeout)
	testThisServerRespondMessages(t, "udp", srv)
	testThisServerRespondMessages(t, "tcp", srv)
}

func TestServer_UDPTruncateMessage(t *testing.T) {
	// Create a test server that returns large response which should be
	// truncated if sent over UDP
	srv := newTestServer(t, &testLargeMsgHandler{})
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})

	// Create client and connect
	client := &Client{
		Timeout: 1 * time.Second,
		Net:     "udp",
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	// Send a test message and check that the response was truncated
	m := createTestMessage()
	res, err := client.Exchange(m, ri)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, dns.RcodeSuccess, res.Rcode)
	require.Len(t, res.Answer, 0)
	require.True(t, res.Truncated)
}

func TestServer_UDPEDNS0_NoTruncate(t *testing.T) {
	// Create a test server that returns large response which should be
	// truncated if sent over UDP
	// However, when EDNS0 is set with the buffer large enough, there should
	// be no truncation
	srv := newTestServer(t, &testLargeMsgHandler{})
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})

	// Create client and connect
	client := &Client{
		Timeout: 1 * time.Second,
		Net:     "udp",
		UDPSize: 7000, // make sure the client will be able to read the response
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	// Send a test message with UDP buffer size large enough
	// and check that the response was NOT truncated
	m := createTestMessage()
	m.Extra = append(m.Extra, &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  2000, // Set large enough UDPSize here
		},
	})
	res, err := client.Exchange(m, ri)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, dns.RcodeSuccess, res.Rcode)
	require.Len(t, res.Answer, 64)
	require.False(t, res.Truncated)
}

func testServerServeCert(t *testing.T, network string) {
	srv := newTestServer(t, &testHandler{})
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})

	client := &Client{
		Net:     network,
		Timeout: 1 * time.Second,
	}

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if network == "tcp" {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	require.Equal(t, ri.ProviderName, srv.server.ProviderName)
	require.True(t, bytes.Equal(srv.server.ResolverCert.ClientMagic[:], ri.ResolverCert.ClientMagic[:]))
	require.Equal(t, srv.server.ResolverCert.EsVersion, ri.ResolverCert.EsVersion)
	require.Equal(t, srv.server.ResolverCert.Signature, ri.ResolverCert.Signature)
	require.Equal(t, srv.server.ResolverCert.NotBefore, ri.ResolverCert.NotBefore)
	require.Equal(t, srv.server.ResolverCert.NotAfter, ri.ResolverCert.NotAfter)
	require.True(t, bytes.Equal(srv.server.ResolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
	require.True(t, bytes.Equal(srv.server.ResolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
}

func testServerRespondMessages(t *testing.T, network string) {
	srv := newTestServer(t, &testHandler{})
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})
	testThisServerRespondMessages(t, network, srv)
}

func testThisServerRespondMessages(t *testing.T, network string, srv *testServer) {
	client := &Client{
		Timeout: 1 * time.Second,
		Net:     network,
	}

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if network == "tcp" {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	require.NoError(t, err)
	require.NotNil(t, ri)

	conn, err := net.Dial(network, stamp.ServerAddrStr)
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		m := createTestMessage()
		res, err := client.ExchangeConn(conn, m, ri)
		require.NoError(t, err)
		assertTestMessageResponse(t, res)
	}
}

type testServer struct {
	server     *Server
	resolverPk ed25519.PublicKey
	udpConn    *net.UDPConn
	tcpListen  net.Listener
}

func (s *testServer) TCPAddr() *net.TCPAddr {
	return s.tcpListen.Addr().(*net.TCPAddr)
}

func (s *testServer) UDPAddr() *net.UDPAddr {
	return s.udpConn.LocalAddr().(*net.UDPAddr)
}

func (s *testServer) Close() error {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()

	err := s.server.Shutdown(ctx)
	_ = s.udpConn.Close()
	_ = s.tcpListen.Close()

	return err
}

func newTestServer(t require.TestingT, handler Handler) *testServer {
	rc, err := GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)
	cert, err := rc.CreateCert()
	require.NoError(t, err)

	s := &Server{
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      handler,
	}

	privateKey, err := HexDecodeKey(rc.PrivateKey)
	require.NoError(t, err)
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	srv := &testServer{
		server:     s,
		resolverPk: publicKey,
	}

	srv.tcpListen, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	srv.udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)

	go func() {
		_ = s.ServeUDP(srv.udpConn)
	}()
	go func() {
		_ = s.ServeTCP(srv.tcpListen)
	}()
	return srv
}

type testHandler struct{}

// ServeDNS - implements Handler interface
func (h *testHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) error {
	res := new(dns.Msg)
	res.SetReply(r)

	answer := new(dns.A)
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeA,
		Ttl:    300,
		Class:  dns.ClassINET,
	}
	// First record is from Google DNS
	answer.A = net.IPv4(8, 8, 8, 8)
	res.Answer = append(res.Answer, answer)

	return rw.WriteMsg(res)
}

// testLargeMsgHandler is a handler that returns a huge response
// used for testing messages truncation
type testLargeMsgHandler struct{}

// ServeDNS - implements Handler interface
func (h *testLargeMsgHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) error {
	res := new(dns.Msg)
	res.SetReply(r)

	for i := 0; i < 64; i++ {
		answer := new(dns.A)
		answer.Hdr = dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Ttl:    300,
			Class:  dns.ClassINET,
		}
		answer.A = net.IPv4(127, 0, 0, byte(i))
		res.Answer = append(res.Answer, answer)
	}

	res.Compress = true
	return rw.WriteMsg(res)
}
