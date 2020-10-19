package dnscrypt

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestParseStamp(t *testing.T) {
	// Google DoH
	stampStr := "sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA"
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)

	if err != nil || stamp.ProviderName == "" {
		t.Fatalf("Could not parse stamp %s: %s", stampStr, err)
	}

	assert.Equal(t, stampStr, stamp.String())
	assert.Equal(t, dnsstamps.StampProtoTypeDoH, stamp.Proto)
	assert.Equal(t, "dns.google.com", stamp.ProviderName)
	assert.Equal(t, "/experimental", stamp.Path)

	// AdGuard DNSCrypt
	stampStr = "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	stamp, err = dnsstamps.NewServerStampFromString(stampStr)

	if err != nil || stamp.ProviderName == "" {
		t.Fatalf("Could not parse stamp %s: %s", stampStr, err)
	}

	assert.Equal(t, stampStr, stamp.String())
	assert.Equal(t, dnsstamps.StampProtoTypeDNSCrypt, stamp.Proto)
	assert.Equal(t, "2.dnscrypt.default.ns1.adguard.com", stamp.ProviderName)
	assert.Equal(t, "", stamp.Path)
	assert.Equal(t, "176.103.130.130:5443", stamp.ServerAddrStr)
	assert.Equal(t, keySize, len(stamp.ServerPk))
}

func TestInvalidStamp(t *testing.T) {
	client := Client{}
	_, err := client.Dial("sdns://AQIAAAAAAAAAFDE")
	assert.NotNil(t, err)
}

func TestTimeoutOnDialError(t *testing.T) {
	// AdGuard DNS pointing to a wrong IP
	stampStr := "sdns://AQIAAAAAAAAADDguOC44Ljg6NTQ0MyDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t"
	client := Client{Timeout: 300 * time.Millisecond}

	_, err := client.Dial(stampStr)
	assert.NotNil(t, err)
	assert.True(t, os.IsTimeout(err))
}

func TestTimeoutOnDialExchange(t *testing.T) {
	// AdGuard DNS
	stampStr := "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	client := Client{Timeout: 300 * time.Millisecond}

	serverInfo, err := client.Dial(stampStr)
	assert.Nil(t, err)

	// Point it to an IP where there's no DNSCrypt server
	serverInfo.ServerAddress = "8.8.8.8:5443"
	req := createTestMessage()

	// Do exchange
	_, err = client.Exchange(req, serverInfo)

	// Check error
	assert.NotNil(t, err)
	assert.True(t, os.IsTimeout(err))
}

func TestFetchCertPublicResolvers(t *testing.T) {
	stamps := []struct {
		stampStr string
	}{
		{
			// AdGuard DNS
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		},
		{
			// AdGuard DNS Family
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
		},
		{
			// AdGuard DNS Unfiltered
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzNjo1NDQzILXoRNa4Oj4-EmjraB--pw3jxfpo29aIFB2_LsBmstr6JTIuZG5zY3J5cHQudW5maWx0ZXJlZC5uczEuYWRndWFyZC5jb20",
		},
		{
			// Cisco OpenDNS
			stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
		},
		{
			// Cisco OpenDNS Family Shield
			stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
		},
	}

	for _, test := range stamps {
		stamp, err := dnsstamps.NewServerStampFromString(test.stampStr)
		assert.Nil(t, err)

		t.Run(stamp.ProviderName, func(t *testing.T) {
			c := &Client{Net: "udp"}
			resolverInfo, err := c.DialStamp(stamp)
			assert.Nil(t, err)
			assert.NotNil(t, resolverInfo)
			assert.True(t, resolverInfo.ResolverCert.VerifyDate())
			assert.True(t, resolverInfo.ResolverCert.VerifySignature(stamp.ServerPk))
		})
	}
}

func TestExchangePublicResolvers(t *testing.T) {
	stamps := []struct {
		stampStr string
	}{
		{
			// AdGuard DNS
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		},
		{
			// AdGuard DNS Family
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
		},
		{
			// AdGuard DNS Unfiltered
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzNjo1NDQzILXoRNa4Oj4-EmjraB--pw3jxfpo29aIFB2_LsBmstr6JTIuZG5zY3J5cHQudW5maWx0ZXJlZC5uczEuYWRndWFyZC5jb20",
		},
		{
			// Cisco OpenDNS
			stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
		},
		{
			// Cisco OpenDNS Family Shield
			stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
		},
	}

	for _, test := range stamps {
		stamp, err := dnsstamps.NewServerStampFromString(test.stampStr)
		assert.Nil(t, err)

		t.Run(stamp.ProviderName, func(t *testing.T) {
			checkDNSCryptServer(t, test.stampStr, "udp")
			checkDNSCryptServer(t, test.stampStr, "tcp")
		})
	}
}

func checkDNSCryptServer(t *testing.T, stampStr string, network string) {
	client := Client{Net: network, Timeout: 10 * time.Second}
	resolverInfo, err := client.Dial(stampStr)
	assert.Nil(t, err)

	req := createTestMessage()

	reply, err := client.Exchange(req, resolverInfo)
	assert.Nil(t, err)
	assertTestMessageResponse(t, reply)
}

func createTestMessage() *dns.Msg {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	return &req
}

func assertTestMessageResponse(t *testing.T, reply *dns.Msg) {
	assert.NotNil(t, reply)
	assert.Equal(t, 1, len(reply.Answer))
	a, ok := reply.Answer[0].(*dns.A)
	assert.True(t, ok)
	assert.Equal(t, net.IPv4(8, 8, 8, 8).To4(), a.A.To4())
}
