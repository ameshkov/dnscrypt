package main

import (
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// ServerArgs is the "server" command arguments
type ServerArgs struct {
	Config      string   `short:"c" long:"config" description:"Path to the DNSCrypt configuration file. Param is required." required:"true"`
	Forward     string   `short:"f" long:"forward" description:"Forwards DNS queries to the specified address" default:"94.140.14.140:53"`
	ListenAddrs []string `short:"l" long:"listen" description:"Listening addresses" default:"0.0.0.0"`
	ListenPorts []int    `short:"p" long:"port" description:"Listening ports" default:"443"`
}

// server runs a DNSCrypt server
func server(args ServerArgs) {
	log.Info("Starting DNSCrypt server")

	b, err := ioutil.ReadFile(args.Config)
	if err != nil {
		log.Fatalf("failed to read the configuration: %v", err)
	}

	rc := dnscrypt.ResolverConfig{}
	err = yaml.Unmarshal(b, &rc)
	if err != nil {
		log.Fatalf("failed to deserialize configuration: %v", err)
	}

	cert, err := rc.CreateCert()
	if err != nil {
		log.Fatalf("failed to generate certificate: %v", err)
	}

	s := &dnscrypt.Server{
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      &forwardHandler{addr: args.Forward},
	}

	tcp, udp := createListeners(args)
	for _, t := range tcp {
		log.Info("Listening to tcp://%s", t.Addr().String())
		listen := t
		go func() { _ = s.ServeTCP(listen) }()
	}
	for _, u := range udp {
		log.Info("Listening to udp://%s", u.LocalAddr().String())
		listen := u
		go func() { _ = s.ServeUDP(listen) }()
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	log.Info("Closing all listeners")
	for _, t := range tcp {
		_ = t.Close()
	}
	for _, u := range udp {
		_ = u.Close()
	}
}

// createListeners creates listeners for our server
func createListeners(args ServerArgs) (tcp []net.Listener, udp []*net.UDPConn) {
	for _, addr := range args.ListenAddrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			log.Fatalf("invalid listen address: %s", addr)
		}

		for _, port := range args.ListenPorts {
			tcpListen, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: port})
			if err != nil {
				log.Fatalf("failed to start TCP listener: %v", err)
			}
			udpListen, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
			if err != nil {
				log.Fatalf("failed to start UDP listener: %v", err)
			}
			tcp = append(tcp, tcpListen)
			udp = append(udp, udpListen)
		}
	}

	return
}

type forwardHandler struct {
	addr string
}

// type check
var _ dnscrypt.Handler = &forwardHandler{}

// ServeDNS implements Handler interface
func (f *forwardHandler) ServeDNS(rw dnscrypt.ResponseWriter, r *dns.Msg) error {
	res, err := dns.Exchange(r, f.addr)
	if err != nil {
		return err
	}
	return rw.WriteMsg(res)
}
