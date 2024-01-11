package dnscrypt

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPadUnpad(t *testing.T) {
	longBuf := make([]byte, 272)
	_, err := rand.Read(longBuf)
	require.NoError(t, err)

	tests := []struct {
		packet       []byte
		expPaddedLen int
	}{
		{[]byte("Example Test DNS packet"), 256},
		{longBuf, 320},
	}
	for i, test := range tests {
		padded := pad(test.packet)
		assert.Equal(t, test.expPaddedLen, len(padded), "test %d", i)

		unpadded, err := unpad(padded)
		assert.Nil(t, err, "test %d", i)
		assert.Equal(t, test.packet, unpadded, "test %d", i)
	}
}
