package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHexEncodeKey(t *testing.T) {
	str := HexEncodeKey([]byte{1, 2, 3, 4})
	require.Equal(t, "01020304", str)
}

func TestHexDecodeKey(t *testing.T) {
	b, err := HexDecodeKey("01:02:03:04")
	require.NoError(t, err)
	require.True(t, bytes.Equal(b, []byte{1, 2, 3, 4}))
}

func TestGenerateResolverConfig(t *testing.T) {
	rc, err := GenerateResolverConfig("example.org", nil)
	require.NoError(t, err)
	require.Equal(t, "2.dnscrypt-cert.example.org", rc.ProviderName)
	require.Equal(t, ed25519.PrivateKeySize*2, len(rc.PrivateKey))
	require.Equal(t, keySize*2, len(rc.ResolverSk))
	require.Equal(t, keySize*2, len(rc.ResolverPk))

	cert, err := rc.CreateCert()
	require.NoError(t, err)

	require.True(t, cert.VerifyDate())

	publicKey, err := HexDecodeKey(rc.PublicKey)
	require.NoError(t, err)
	require.True(t, cert.VerifySignature(publicKey))
}
