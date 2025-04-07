package xsecretbox

import (
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

const (
	// KeySize is what the name suggests
	KeySize = chacha20.KeySize
	// NonceSize is what the name suggests
	NonceSize = chacha20.NonceSizeX
	// TagSize is what the name suggests
	TagSize = poly1305.TagSize
	// BlockSize is what the name suggests
	BlockSize = 64
)

// Seal does what the name suggests
func Seal(out, nonce, message, key []byte) []byte {
	if len(nonce) != NonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != KeySize {
		panic("unsupported key size")
	}

	var firstBlock [BlockSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [KeySize]byte
	copy(polyKey[:], firstBlock[:KeySize])

	ret, out := sliceForAppend(out, TagSize+len(message))
	firstMessageBlock := message
	if len(firstMessageBlock) > (BlockSize - KeySize) {
		firstMessageBlock = firstMessageBlock[:(BlockSize - KeySize)]
	}

	tagOut := out
	out = out[poly1305.TagSize:]
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[(BlockSize-KeySize)+i] ^ x
	}
	message = message[len(firstMessageBlock):]
	ciphertext := out
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, message)

	var tag [TagSize]byte
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(ciphertext)
	hash.Sum(tag[:0])
	copy(tagOut, tag[:])

	return ret
}

// Open does what the name suggests
func Open(out, nonce, box, key []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != KeySize {
		panic("unsupported key size")
	}
	if len(box) < TagSize {
		return nil, errors.New("ciphertext is too short")
	}

	var firstBlock [BlockSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [KeySize]byte
	copy(polyKey[:], firstBlock[:KeySize])

	var tag [TagSize]byte
	ciphertext := box[TagSize:]
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(ciphertext)
	hash.Sum(tag[:0])
	if subtle.ConstantTimeCompare(tag[:], box[:TagSize]) != 1 {
		return nil, errors.New("ciphertext authentication failed")
	}

	ret, out := sliceForAppend(out, len(ciphertext))

	firstMessageBlock := ciphertext
	if len(firstMessageBlock) > (BlockSize - KeySize) {
		firstMessageBlock = firstMessageBlock[:(BlockSize - KeySize)]
	}
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[(BlockSize-KeySize)+i] ^ x
	}
	ciphertext = ciphertext[len(firstMessageBlock):]
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, ciphertext)
	return ret, nil
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
