package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHexEncodeKey(t *testing.T) {
	str := HexEncodeKey([]byte{1, 2, 3, 4})
	assert.Equal(t, "01020304", str)
}

func TestHexDecodeKey(t *testing.T) {
	b, err := HexDecodeKey("01:02:03:04")
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(b, []byte{1, 2, 3, 4}))
}

func TestGenerateResolverConfig(t *testing.T) {
	rc, err := GenerateResolverConfig("example.org", nil)
	assert.Nil(t, err)
	assert.Equal(t, "2.dnscrypt-cert.example.org", rc.ProviderName)
	assert.Equal(t, ed25519.PrivateKeySize*2, len(rc.PrivateKey))
	assert.Equal(t, keySize*2, len(rc.ResolverSk))
	assert.Equal(t, keySize*2, len(rc.ResolverPk))

	cert, err := rc.CreateCert()
	assert.Nil(t, err)

	assert.True(t, cert.VerifyDate())

	publicKey, err := HexDecodeKey(rc.PublicKey)
	assert.Nil(t, err)
	assert.True(t, cert.VerifySignature(publicKey))
}
