package dnscrypt

import (
	"bytes"
	"net"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

type encryptionFunc func(m *dns.Msg, q EncryptedQuery) ([]byte, error)

// UDPResponseWriter - ResponseWriter implementation for UDP
type UDPResponseWriter struct {
	udpConn *net.UDPConn    // UDP connection
	sess    *dns.SessionUDP // SessionUDP (necessary to use dns.WriteToSessionUDP)
	encrypt encryptionFunc  // DNSCRypt encryption function
	req     *dns.Msg        // DNS query that was processed
	query   EncryptedQuery  // DNSCrypt query properties
}

// type check
var _ ResponseWriter = &UDPResponseWriter{}

// LocalAddr - server socket local address
func (w *UDPResponseWriter) LocalAddr() net.Addr {
	return w.udpConn.LocalAddr()
}

// RemoteAddr - client's address
func (w *UDPResponseWriter) RemoteAddr() net.Addr {
	return w.udpConn.RemoteAddr()
}

// WriteMsg - writes DNS message to the client
func (w *UDPResponseWriter) WriteMsg(m *dns.Msg) error {
	m.Truncate(dnsSize("udp", w.req))

	res, err := w.encrypt(m, w.query)
	if err != nil {
		log.Tracef("Failed to encrypt the DNS query: %v", err)
		return err
	}
	_, err = dns.WriteToSessionUDP(w.udpConn, res, w.sess)
	return err
}

// ServeUDP - listens to UDP connections, queries are then processed by Server.Handler.
// It blocks the calling goroutine and to stop it you need to close the listener.
func (s *Server) ServeUDP(l *net.UDPConn) error {
	var once sync.Once
	unlock := func() { once.Do(s.lock.Unlock) }
	s.lock.Lock()
	defer unlock()

	// Check that server is properly configured
	if !s.validate() {
		return ErrServerConfig
	}

	// set UDP options to allow receiving OOB data
	err := setUDPSocketOptions(l)
	if err != nil {
		return err
	}

	// Serialize the cert right away and prepare it to be sent to the client
	certBuf, err := s.ResolverCert.Serialize()
	if err != nil {
		return err
	}
	certTxt := packTxtString(certBuf)

	// Mark the server as started if needed
	s.init()
	s.started = true

	// No need to lock anymore
	unlock()

	// Track active UDP listener
	s.lock.Lock()
	s.udpListeners[l] = struct{}{}
	s.lock.Unlock()

	// Tracks UDP handling goroutines
	udpWg := &sync.WaitGroup{}

	// Track active goroutine
	s.wg.Add(1)
	defer func() {
		// Wait until UDP messages are processed
		udpWg.Wait()
		s.lock.Lock()
		delete(s.udpListeners, l)
		s.lock.Unlock()
		s.wg.Done()
	}()

	log.Info("Entering DNSCrypt UDP listening loop on udp://%s", l.LocalAddr().String())

	for s.isStarted() {
		b, sess, err := s.readUDPMsg(l)

		// Check the error code and exit loop if necessary
		if err != nil {
			if !s.isStarted() {
				// Stopped gracefully
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// Note that timeout errors will be here (i.e. hitting ReadDeadline)
				continue
			}
			if isConnClosed(err) {
				log.Info("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
			} else {
				log.Info("got error when reading from UDP listen: %s", err)
			}
			return err
		}

		if len(b) < minDNSPacketSize {
			// Ignore the packets that are too short
			continue
		}

		udpWg.Add(1)
		go func() {
			s.serveUDPMsg(b, certTxt, sess, l)
			udpWg.Done()
		}()
	}

	return nil
}

// readUDPMsg - reads incoming UDP message
func (s *Server) readUDPMsg(l *net.UDPConn) ([]byte, *dns.SessionUDP, error) {
	_ = l.SetReadDeadline(time.Now().Add(readTimeout))
	b := make([]byte, dns.MinMsgSize)
	n, sess, err := dns.ReadFromSessionUDP(l, b)
	if err != nil {
		return nil, nil, err
	}

	return b[:n], sess, err
}

// serveUDPMsg - handles incoming DNS message
func (s *Server) serveUDPMsg(b []byte, certTxt string, sess *dns.SessionUDP, l *net.UDPConn) {
	if bytes.Equal(b[:clientMagicSize], s.ResolverCert.ClientMagic[:]) {
		// This is an encrypted message, we should decrypt it
		m, q, err := s.decrypt(b)
		if err == nil {
			rw := &UDPResponseWriter{
				udpConn: l,
				sess:    sess,
				encrypt: s.encrypt,
				req:     m,
				query:   q,
			}
			_ = s.serveDNS(rw, m)
		} else {
			log.Tracef("Failed to decrypt incoming message len=%d: %v", len(b), err)
		}
	} else {
		// Most likely this a DNS message requesting the certificate
		reply, err := s.handleHandshake(b, certTxt)
		if err != nil {
			log.Tracef("Failed to process a plain DNS query: %v", err)
		}
		if err == nil {
			_, _ = dns.WriteToSessionUDP(l, reply, sess)
		}
	}
}

// setUDPSocketOptions - this is necessary to be able to use dns.ReadFromSessionUDP / dns.WriteToSessionUDP
func setUDPSocketOptions(conn *net.UDPConn) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	// Try setting the flags for both families and ignore the errors unless they
	// both error.
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return err4
	}
	return nil
}
