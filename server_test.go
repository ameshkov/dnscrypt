package dnscrypt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestServer_Shutdown(t *testing.T) {
	srv := newTestServer(t, &testHandler{})
	time.Sleep(defaultReadTimeout)
	assert.NoError(t, srv.Close())
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

func testServerServeCert(t *testing.T, network string) {
	srv := newTestServer(t, &testHandler{})
	t.Cleanup(func() {
		assert.NoError(t, srv.Close())
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
	assert.NoError(t, err)
	assert.NotNil(t, ri)

	assert.Equal(t, ri.ProviderName, srv.server.ProviderName)
	assert.True(t, bytes.Equal(srv.server.ResolverCert.ClientMagic[:], ri.ResolverCert.ClientMagic[:]))
	assert.Equal(t, srv.server.ResolverCert.EsVersion, ri.ResolverCert.EsVersion)
	assert.Equal(t, srv.server.ResolverCert.Signature, ri.ResolverCert.Signature)
	assert.Equal(t, srv.server.ResolverCert.NotBefore, ri.ResolverCert.NotBefore)
	assert.Equal(t, srv.server.ResolverCert.NotAfter, ri.ResolverCert.NotAfter)
	assert.True(t, bytes.Equal(srv.server.ResolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
	assert.True(t, bytes.Equal(srv.server.ResolverCert.ResolverPk[:], ri.ResolverCert.ResolverPk[:]))
}

func testServerRespondMessages(t *testing.T, network string) {
	srv := newTestServer(t, &testHandler{})
	t.Cleanup(func() {
		assert.NoError(t, srv.Close())
	})

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
	assert.NoError(t, err)
	assert.NotNil(t, ri)

	conn, err := net.Dial(network, stamp.ServerAddrStr)
	assert.NoError(t, err)

	for i := 0; i < 10; i++ {
		m := createTestMessage()
		res, err := client.ExchangeConn(conn, m, ri)
		assert.NoError(t, err)
		assertTestMessageResponse(t, res)
	}
}

type testServer struct {
	server     *Server
	resolverPk ed25519.PublicKey
	udpConn    *net.UDPConn
	tcpListen  net.Listener
	handler    Handler
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

func newTestServer(t assert.TestingT, handler Handler) *testServer {
	rc, err := GenerateResolverConfig("example.org", nil)
	assert.NoError(t, err)
	cert, err := rc.CreateCert()
	assert.NoError(t, err)

	s := &Server{
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      handler,
	}

	privateKey, err := HexDecodeKey(rc.PrivateKey)
	assert.NoError(t, err)
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	srv := &testServer{
		server:     s,
		resolverPk: publicKey,
	}

	srv.tcpListen, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	assert.NoError(t, err)
	srv.udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	assert.NoError(t, err)

	go s.ServeUDP(srv.udpConn)
	go s.ServeTCP(srv.tcpListen)
	return srv
}

type testHandler struct{}

// ServeDNS - implements Handler interface
func (h *testHandler) ServeDNS(rw ResponseWriter, r *dns.Msg) error {
	// Google DNS
	res := new(dns.Msg)
	res.SetReply(r)
	answer := new(dns.A)
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeA,
		Ttl:    300,
		Class:  dns.ClassINET,
	}
	answer.A = net.IPv4(8, 8, 8, 8)
	res.Answer = append(res.Answer, answer)
	return rw.WriteMsg(res)
}
