package dnscrypt

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestParseStamp(t *testing.T) {
	// Google DoH
	stampStr := "sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA"
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)

	if err != nil || stamp.ProviderName == "" {
		t.Fatalf("Could not parse stamp %s: %s", stampStr, err)
	}

	require.Equal(t, stampStr, stamp.String())
	require.Equal(t, dnsstamps.StampProtoTypeDoH, stamp.Proto)
	require.Equal(t, "dns.google.com", stamp.ProviderName)
	require.Equal(t, "/experimental", stamp.Path)

	// AdGuard DNSCrypt
	stampStr = "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	stamp, err = dnsstamps.NewServerStampFromString(stampStr)

	if err != nil || stamp.ProviderName == "" {
		t.Fatalf("Could not parse stamp %s: %s", stampStr, err)
	}

	require.Equal(t, stampStr, stamp.String())
	require.Equal(t, dnsstamps.StampProtoTypeDNSCrypt, stamp.Proto)
	require.Equal(t, "2.dnscrypt.default.ns1.adguard.com", stamp.ProviderName)
	require.Equal(t, "", stamp.Path)
	require.Equal(t, "176.103.130.130:5443", stamp.ServerAddrStr)
	require.Equal(t, keySize, len(stamp.ServerPk))
}

func TestInvalidStamp(t *testing.T) {
	client := Client{}
	_, err := client.Dial("sdns://AQIAAAAAAAAAFDE")
	require.NotNil(t, err)
}

func TestTimeoutOnDialError(t *testing.T) {
	// AdGuard DNS pointing to a wrong IP
	stampStr := "sdns://AQIAAAAAAAAADDguOC44Ljg6NTQ0MyDRK0fyUtzywrv4mRCG6vec5EldixbIoMQyLlLKPzkIcyIyLmRuc2NyeXB0LmRlZmF1bHQubnMxLmFkZ3VhcmQuY29t"
	client := Client{Timeout: 300 * time.Millisecond}

	_, err := client.Dial(stampStr)
	require.NotNil(t, err)
	require.True(t, os.IsTimeout(err))
}

func TestTimeoutOnDialExchange(t *testing.T) {
	// AdGuard DNS
	stampStr := "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	client := Client{Timeout: 300 * time.Millisecond}

	serverInfo, err := client.Dial(stampStr)
	require.NoError(t, err)

	// Point it to an IP where there's no DNSCrypt server
	serverInfo.ServerAddress = "8.8.8.8:5443"
	req := createTestMessage()

	// Do exchange
	_, err = client.Exchange(req, serverInfo)

	// Check error
	require.NotNil(t, err)
	require.True(t, os.IsTimeout(err))
}

func TestFetchCertPublicResolvers(t *testing.T) {
	testCases := []struct {
		name     string
		stampStr string
	}{
		{
			name:     "AdGuard DNS",
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		},
		{
			name:     "AdGuard DNS Family",
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
		},
		{
			name:     "AdGuard DNS Unfiltered",
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzNjo1NDQzILXoRNa4Oj4-EmjraB--pw3jxfpo29aIFB2_LsBmstr6JTIuZG5zY3J5cHQudW5maWx0ZXJlZC5uczEuYWRndWFyZC5jb20",
		},
		{
			name:     "Cisco OpenDNS",
			stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
		},
		{
			name:     "Cisco OpenDNS Family Shield",
			stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
		},
		{
			name:     "Quad9",
			stampStr: "sdns://AQYAAAAAAAAAEzE0OS4xMTIuMTEyLjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stamp, err := dnsstamps.NewServerStampFromString(tc.stampStr)
			require.NoError(t, err)

			c := &Client{
				Net:     "udp",
				Timeout: time.Second * 5,
			}
			resolverInfo, err := c.DialStamp(stamp)
			require.NoError(t, err)
			require.NotNil(t, resolverInfo)
			require.True(t, resolverInfo.ResolverCert.VerifyDate())
			require.True(t, resolverInfo.ResolverCert.VerifySignature(stamp.ServerPk))
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
		require.NoError(t, err)

		t.Run(stamp.ProviderName, func(t *testing.T) {
			checkDNSCryptServer(t, test.stampStr, "udp")
			checkDNSCryptServer(t, test.stampStr, "tcp")
		})
	}
}

func checkDNSCryptServer(t *testing.T, stampStr string, network string) {
	client := Client{Net: network, Timeout: 10 * time.Second}
	resolverInfo, err := client.Dial(stampStr)
	require.NoError(t, err)

	req := createTestMessage()

	reply, err := client.Exchange(req, resolverInfo)
	require.NoError(t, err)
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

func assertTestMessageResponse(t require.TestingT, reply *dns.Msg) {
	require.NotNil(t, reply)
	require.Equal(t, 1, len(reply.Answer))
	a, ok := reply.Answer[0].(*dns.A)
	require.True(t, ok)
	require.Equal(t, net.IPv4(8, 8, 8, 8).To4(), a.A.To4())
}
