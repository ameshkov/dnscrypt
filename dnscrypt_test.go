package dnscrypt

import (
	"log"
	"net"
	"testing"
	"time"

	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
)

func TestParseStamp(t *testing.T) {

	// Google DoH
	stampStr := "sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA"
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)

	if err != nil || stamp.ProviderName == "" {
		t.Fatalf("Could not parse stamp %s: %s", stampStr, err)
	}

	log.Println(stampStr)
	log.Printf("Proto=%s\n", stamp.Proto.String())
	log.Printf("ProviderName=%s\n", stamp.ProviderName)
	log.Printf("Path=%s\n", stamp.Path)
	log.Println("")

	// AdGuard DNSCrypt
	stampStr = "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	stamp, err = dnsstamps.NewServerStampFromString(stampStr)

	if err != nil || stamp.ProviderName == "" {
		t.Fatalf("Could not parse stamp %s: %s", stampStr, err)
	}

	log.Println(stampStr)
	log.Printf("Proto=%s\n", stamp.Proto.String())
	log.Printf("ProviderName=%s\n", stamp.ProviderName)
	log.Printf("Path=%s\n", stamp.Path)
	log.Printf("ServerAddrStr=%s\n", stamp.ServerAddrStr)
	log.Println("")
}

func TestDnsCryptResolver(t *testing.T) {

	stamps := []struct {
		stampStr string
		udp      bool
	}{
		{
			// AdGuard DNS
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
			udp:      true,
		},
		{
			// AdGuard DNS Family
			stampStr: "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
			udp:      true,
		},
		{
			// Cisco OpenDNS
			stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
			udp:      true,
		},
		{
			// Cisco OpenDNS Family Shield
			stampStr: "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
			udp:      true,
		},
		{
			// Quad9 (anycast) dnssec/no-log/filter 9.9.9.9
			stampStr: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
			udp:      true,
		},
		{
			// https://securedns.eu/
			stampStr: "sdns://AQcAAAAAAAAAEzE0Ni4xODUuMTY3LjQzOjUzNTMgs6WXaRRXWwSJ4Z-unEPmefryjFcYlwAxf3u0likfsJUcMi5kbnNjcnlwdC1jZXJ0LnNlY3VyZWRucy5ldQ",
			udp:      true,
		},
		{
			// Yandex DNS
			stampStr: "sdns://AQQAAAAAAAAAEDc3Ljg4LjguNzg6MTUzNTMg04TAccn3RmKvKszVe13MlxTUB7atNgHhrtwG1W1JYyciMi5kbnNjcnlwdC1jZXJ0LmJyb3dzZXIueWFuZGV4Lm5ldA",
			udp:      true,
		},
	}

	for _, test := range stamps {

		if test.udp {
			checkDnsCryptServer(t, test.stampStr, "udp")
		}
		checkDnsCryptServer(t, test.stampStr, "tcp")
	}
}

func checkDnsCryptServer(t *testing.T, stampStr string, proto string) {

	client := Client{Proto: proto, Timeout: 10 * time.Second}
	serverInfo, rtt, err := client.Dial(stampStr)
	if err != nil {
		t.Fatalf("Could not establish connection with %s", stampStr)
	}

	log.Printf("Established a connection with %s, rtt=%v, proto=%s", serverInfo.ProviderName, rtt, proto)
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "google-public-dns-a.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	reply, rtt, err := client.Exchange(&req, serverInfo)
	if err != nil {
		t.Fatalf("Couldn't talk to upstream %s: %s", serverInfo.ProviderName, err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("DNS upstream %s returned reply with wrong number of answers - %d", serverInfo.ProviderName, len(reply.Answer))
	}
	if a, ok := reply.Answer[0].(*dns.A); ok {
		if !net.IPv4(8, 8, 8, 8).Equal(a.A) {
			t.Fatalf("DNS upstream %s returned wrong answer instead of 8.8.8.8: %v", serverInfo.ProviderName, a.A)
		}
	} else {
		t.Fatalf("DNS upstream %s returned wrong answer type instead of A: %v", serverInfo.ProviderName, reply.Answer[0])
	}
	log.Printf("Got proper response from %s, rtt=%v, proto=%s", serverInfo.ProviderName, rtt, proto)
}
