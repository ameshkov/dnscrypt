package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDNSCryptQueryEncryptDecryptXSalsa20Poly1305(t *testing.T) {
	testDNSCryptQueryEncryptDecrypt(t, XSalsa20Poly1305)
}

func TestDNSCryptQueryEncryptDecryptXChacha20Poly1305(t *testing.T) {
	testDNSCryptQueryEncryptDecrypt(t, XChacha20Poly1305)
}

func testDNSCryptQueryEncryptDecrypt(t *testing.T, esVersion CryptoConstruction) {
	// Generate the secret/public pairs
	clientSecretKey, clientPublicKey := generateRandomKeyPair()
	serverSecretKey, serverPublicKey := generateRandomKeyPair()

	// Generate client shared key
	clientSharedKey, err := computeSharedKey(esVersion, &clientSecretKey, &serverPublicKey)
	assert.NoError(t, err)

	clientMagic := [clientMagicSize]byte{}
	_, _ = rand.Read(clientMagic[:])

	q1 := EncryptedQuery{
		EsVersion:   esVersion,
		ClientPk:    clientPublicKey,
		ClientMagic: clientMagic,
	}

	// Generate random packet
	packet := make([]byte, 100)
	_, _ = rand.Read(packet[:])

	// Encrypt it
	encrypted, err := q1.Encrypt(packet, clientSharedKey)
	assert.NoError(t, err)

	// Now let's try decrypting it
	q2 := EncryptedQuery{
		EsVersion:   esVersion,
		ClientMagic: clientMagic,
	}

	// Decrypt it
	decrypted, err := q2.Decrypt(encrypted, serverSecretKey)
	assert.NoError(t, err)

	// Check that packet is the same
	assert.True(t, bytes.Equal(packet, decrypted))
}
