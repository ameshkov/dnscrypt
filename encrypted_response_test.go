package dnscrypt

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/ameshkov/dnscrypt/v2/xsecretbox"
	"github.com/stretchr/testify/require"
)

func TestDNSCryptResponseEncryptDecryptXSalsa20Poly1305(t *testing.T) {
	testDNSCryptResponseEncryptDecrypt(t, XSalsa20Poly1305)
}

func TestDNSCryptResponseEncryptDecryptXChacha20Poly1305(t *testing.T) {
	testDNSCryptResponseEncryptDecrypt(t, XChacha20Poly1305)
}

func testDNSCryptResponseEncryptDecrypt(t *testing.T, esVersion CryptoConstruction) {
	// Generate the secret/public pairs
	clientSecretKey, clientPublicKey := generateRandomKeyPair()
	serverSecretKey, serverPublicKey := generateRandomKeyPair()

	// Generate client shared key
	clientSharedKey, err := computeSharedKey(esVersion, &clientSecretKey, &serverPublicKey)
	require.NoError(t, err)

	// Generate server shared key
	serverSharedKey, err := computeSharedKey(esVersion, &serverSecretKey, &clientPublicKey)
	require.NoError(t, err)

	r1 := &EncryptedResponse{
		EsVersion: esVersion,
	}
	// Fill client-nonce
	_, _ = rand.Read(r1.Nonce[:nonceSize/12])

	// Generate random packet
	packet := make([]byte, 100)
	_, _ = rand.Read(packet[:])

	// Encrypt it
	encrypted, err := r1.Encrypt(packet, serverSharedKey)
	require.NoError(t, err)

	// Now let's try decrypting it
	r2 := &EncryptedResponse{
		EsVersion: esVersion,
	}

	// Decrypt it
	decrypted, err := r2.Decrypt(encrypted, clientSharedKey)
	require.NoError(t, err)

	// Check that packet is the same
	require.True(t, bytes.Equal(packet, decrypted))

	// Now check invalid data (some random stuff)
	_, err = r2.Decrypt(packet, clientSharedKey)
	require.NotNil(t, err)

	// Empty array
	_, err = r2.Decrypt([]byte{}, clientSharedKey)
	require.NotNil(t, err)

	// Minimum valid size
	b := make([]byte, len(resolverMagic)+nonceSize+xsecretbox.TagSize+minDNSPacketSize)
	_, _ = rand.Read(b)
	_, err = r2.Decrypt(b, clientSharedKey)
	require.NotNil(t, err)
}
