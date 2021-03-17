package dnscrypt

import (
	"bytes"
	"net"
	"sync"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// TCPResponseWriter - ResponseWriter implementation for TCP
type TCPResponseWriter struct {
	tcpConn net.Conn
	encrypt encryptionFunc
	req     *dns.Msg
	query   EncryptedQuery
}

// type check
var _ ResponseWriter = &TCPResponseWriter{}

// LocalAddr - server socket local address
func (w *TCPResponseWriter) LocalAddr() net.Addr {
	return w.tcpConn.LocalAddr()
}

// RemoteAddr - client's address
func (w *TCPResponseWriter) RemoteAddr() net.Addr {
	return w.tcpConn.RemoteAddr()
}

// WriteMsg - writes DNS message to the client
func (w *TCPResponseWriter) WriteMsg(m *dns.Msg) error {
	m.Truncate(dnsSize("tcp", w.req))

	res, err := w.encrypt(m, w.query)
	if err != nil {
		log.Tracef("Failed to encrypt the DNS query: %v", err)
		return err
	}

	return writePrefixed(res, w.tcpConn)
}

// ServeTCP - listens to TCP connections, queries are then processed by Server.Handler.
// It blocks the calling goroutine and to stop it you need to close the listener.
func (s *Server) ServeTCP(l net.Listener) error {
	var once sync.Once
	unlock := func() { once.Do(s.lock.Unlock) }
	s.lock.Lock()
	defer unlock()

	// Check that server is properly configured
	if !s.validate() {
		return ErrServerConfig
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

	log.Info("Entering DNSCrypt TCP listening loop tcp://%s", l.Addr().String())

	// Track active TCP listener
	s.lock.Lock()
	s.tcpListeners[l] = struct{}{}
	s.lock.Unlock()

	// Tracks TCP connection handling goroutines
	tcpWg := sync.WaitGroup{}

	// Track active goroutine
	s.wg.Add(1)
	defer func() {
		// Wait until all TCP connections are processed
		tcpWg.Wait()

		s.lock.Lock()
		delete(s.tcpListeners, l)
		s.lock.Unlock()

		s.wg.Done()
	}()

	for s.isStarted() {
		conn, err := l.Accept()

		// Check the error code and exit loop if necessary
		if err != nil {
			if !s.isStarted() {
				// Stopped gracefully
				break
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
			break
		}

		// If we got here, the connection is alive
		s.lock.Lock()
		// Track the connection to allow unblocking reads on shutdown.
		s.tcpConns[conn] = struct{}{}
		s.lock.Unlock()

		tcpWg.Add(1)
		go func() {
			_ = s.handleTCPConnection(conn, certTxt)

			// Clean up
			_ = conn.Close()
			s.lock.Lock()
			delete(s.tcpConns, conn)
			s.lock.Unlock()
			tcpWg.Done()
		}()
	}

	return nil
}

// handleTCPMsg - handles a single TCP message. If this method returns error
// the connection will be closed
func (s *Server) handleTCPMsg(b []byte, conn net.Conn, certTxt string) error {
	if len(b) < minDNSPacketSize {
		// Ignore the packets that are too short
		return ErrTooShort
	}

	if bytes.Equal(b[:clientMagicSize], s.ResolverCert.ClientMagic[:]) {
		// This is an encrypted message, we should decrypt it
		m, q, err := s.decrypt(b)
		if err != nil {
			log.Tracef("failed to decrypt incoming message: %v", err)
			return err
		}
		rw := &TCPResponseWriter{
			tcpConn: conn,
			encrypt: s.encrypt,
			req:     m,
			query:   q,
		}
		err = s.serveDNS(rw, m)
		if err != nil {
			return err
		}
	} else {
		// Most likely this a DNS message requesting the certificate
		reply, err := s.handleHandshake(b, certTxt)
		if err != nil {
			log.Tracef("Failed to process a plain DNS query: %v", err)
			return err
		}
		err = writePrefixed(reply, conn)
		if err != nil {
			return err
		}
	}

	return nil
}

// handleTCPConnection - handles all queries that are coming to the
// specified TCP connection.
func (s *Server) handleTCPConnection(conn net.Conn, certTxt string) error {
	for s.isStarted() {
		b, err := readPrefixed(conn)
		if err != nil {
			return err
		}

		err = s.handleTCPMsg(b, conn, certTxt)
		if err != nil {
			return err
		}
	}

	return nil
}
