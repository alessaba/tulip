package main

// PCAP-over-IP stream decryption.
//
// Wire frame (encryption enabled):
//
//	[4-byte big-endian length L][12-byte nonce][L bytes ciphertext+16-byte tag]
//
// Both AES-128-GCM and ChaCha20-Poly1305 use a 12-byte nonce and a 16-byte tag,
// so a single frame format and a single cipher.AEAD reader handle both schemes.
// The matching encryption is performed by the firewall (POBA-Firewall).

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

const pcapNonceLen = 12

// pcapMaxFrame caps the per-frame allocation. The channel may be public, so an
// attacker without the key can still send a hostile length prefix; refuse
// oversized frames instead of allocating arbitrary memory.
const pcapMaxFrame = 1 << 20

// newPcapAEAD builds the AEAD for the configured scheme, validating key length.
func newPcapAEAD(scheme string, key []byte) (cipher.AEAD, error) {
	switch scheme {
	case "aes-128-gcm":
		if len(key) != 16 {
			return nil, fmt.Errorf("aes-128-gcm requires a 16-byte key (32 hex chars), got %d", len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "chacha20-poly1305":
		if len(key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("chacha20-poly1305 requires a %d-byte key (%d hex chars), got %d",
				chacha20poly1305.KeySize, chacha20poly1305.KeySize*2, len(key))
		}
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unknown encryption scheme: %q (valid: aes-128-gcm, chacha20-poly1305)", scheme)
	}
}

// decryptPcapStream reads length-prefixed AEAD frames from src, decrypts them and
// writes the plaintext PCAP byte stream to dst. It runs until src ends or errors.
// dst is closed on return so a downstream PCAP reader sees EOF.
func decryptPcapStream(src io.Reader, dst *os.File, aead cipher.AEAD) error {
	defer dst.Close()

	if aead.NonceSize() != pcapNonceLen {
		return fmt.Errorf("unexpected AEAD nonce size %d, want %d", aead.NonceSize(), pcapNonceLen)
	}

	lenBuf := make([]byte, 4)
	nonce := make([]byte, pcapNonceLen)
	for {
		if _, err := io.ReadFull(src, lenBuf); err != nil {
			return err // io.EOF on clean disconnect
		}
		n := binary.BigEndian.Uint32(lenBuf)
		if n == 0 || n > pcapMaxFrame {
			return errors.New("invalid PCAP frame length")
		}
		if _, err := io.ReadFull(src, nonce); err != nil {
			return err
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(src, ct); err != nil {
			return err
		}
		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return err // tampered, wrong key, or scheme mismatch
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
	}
}
