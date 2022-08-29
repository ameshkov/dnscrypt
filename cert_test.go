package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCertSerialize(t *testing.T) {
	cert, publicKey, _ := generateValidCert(t)

	// not empty anymore
	require.False(t, bytes.Equal(cert.Signature[:], make([]byte, 64)))

	// verify the signature
	require.True(t, cert.VerifySignature(publicKey))

	// serialize
	b, err := cert.Serialize()
	require.NoError(t, err)
	require.Equal(t, 124, len(b))

	// check that we can deserialize it
	cert2 := Cert{}
	err = cert2.Deserialize(b)
	require.NoError(t, err)
	require.Equal(t, cert.Serial, cert2.Serial)
	require.Equal(t, cert.NotBefore, cert2.NotBefore)
	require.Equal(t, cert.NotAfter, cert2.NotAfter)
	require.Equal(t, cert.EsVersion, cert2.EsVersion)
	require.True(t, bytes.Equal(cert.ClientMagic[:], cert2.ClientMagic[:]))
	require.True(t, bytes.Equal(cert.ResolverPk[:], cert2.ResolverPk[:]))
	require.True(t, bytes.Equal(cert.Signature[:], cert2.Signature[:]))
}

func TestCertDeserialize(t *testing.T) {
	// dig -t txt 2.dnscrypt-cert.opendns.com. -p 443 @208.67.220.220
	certBytes, err := os.ReadFile("testdata/dnscrypt-cert.opendns.txt")
	require.NoError(t, err)

	b, err := unpackTxtString(string(certBytes))
	require.NoError(t, err)

	cert := &Cert{}
	err = cert.Deserialize(b)
	require.NoError(t, err)
	require.Equal(t, uint32(1574811744), cert.Serial)
	require.Equal(t, XSalsa20Poly1305, cert.EsVersion)
	require.Equal(t, uint32(1574811744), cert.NotBefore)
	require.Equal(t, uint32(1606347744), cert.NotAfter)
}

func generateValidCert(t *testing.T) (*Cert, ed25519.PublicKey, ed25519.PrivateKey) {
	cert := &Cert{
		Serial:    1,
		NotAfter:  uint32(time.Now().Add(1 * time.Hour).Unix()),
		NotBefore: uint32(time.Now().Add(-1 * time.Hour).Unix()),
		EsVersion: XChacha20Poly1305,
	}

	// generate short-term resolver private key
	resolverSk, resolverPk := generateRandomKeyPair()
	copy(cert.ResolverPk[:], resolverPk[:])
	copy(cert.ResolverSk[:], resolverSk[:])

	// empty at first
	require.True(t, bytes.Equal(cert.Signature[:], make([]byte, 64)))

	// generate private key
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// sign the data
	cert.Sign(privateKey)

	return cert, publicKey, privateKey
}
