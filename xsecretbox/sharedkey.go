package xsecretbox

import (
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
)

// SharedKey computes a shared secret compatible with the one used by
// `crypto_box_xchacha20poly1305`.
func SharedKey(secretKey [curve25519.ScalarSize]byte, publicKey [curve25519.PointSize]byte) ([KeySize]byte, error) {
	var sharedKey [curve25519.PointSize]byte

	sk, err := curve25519.X25519(secretKey[:], publicKey[:])
	if err != nil {
		return sharedKey, err
	}

	c := byte(0)
	for i := 0; i < KeySize; i++ {
		sharedKey[i] = sk[i]
		c |= sk[i]
	}
	if c == 0 {
		return sharedKey, errors.New("weak public key")
	}
	var nonce [16]byte // HChaCha20 uses only 16 bytes long nonces

	hRes, err := chacha20.HChaCha20(sharedKey[:], nonce[:])
	if err != nil {
		return [KeySize]byte{}, err
	}

	return ([KeySize]byte)(hRes), nil
}
