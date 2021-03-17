package dnscrypt

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"

	"github.com/stretchr/testify/assert"
)

func BenchmarkServeUDP(b *testing.B) {
	benchmarkServe(b, "udp")
}

func BenchmarkServeTCP(b *testing.B) {
	benchmarkServe(b, "tcp")
}

func benchmarkServe(b *testing.B, network string) {
	b.StopTimer()
	srv := newTestServer(b, &testHandler{})
	defer func() {
		err := srv.Close()
		assert.Nil(b, err)
	}()

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
	assert.NoError(b, err)
	assert.NotNil(b, ri)

	conn, err := net.Dial(network, stamp.ServerAddrStr)
	assert.NoError(b, err)

	b.ReportAllocs()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		m := createTestMessage()
		res, err := client.ExchangeConn(conn, m, ri)
		assert.NoError(b, err)
		assertTestMessageResponse(b, res)
	}
	b.StopTimer()
}
