// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const (
	certificateFile = "the certificate file"
	keyFile         = "the key file"
	// othersReadBits are the group and other read bits of a file's mode.
	othersReadBits = 0o044
	// rsaLeastBits is the shortest RSA key the engine takes.
	rsaLeastBits = 2048

	certificateBlock = "CERTIFICATE"
	keySuffix        = " PRIVATE KEY"
	pkcs8Block       = "PRIVATE KEY"
	ecBlock          = "EC PRIVATE KEY"
	rsaBlock         = "RSA PRIVATE KEY"
	encryptedBlock   = "ENCRYPTED PRIVATE KEY"
)

// Object identifiers of the key algorithms the engine serves.
var (
	oidRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// refusal is the only error text ReadCertificate gives: the file it is about and the sentinel,
// since the operating system's and crypto/x509's text can quote the file.
func refusal(file string, sentinel error) error {
	return fmt.Errorf("%s: %w", file, sentinel)
}

func isKeyBlock(block *pem.Block) bool {
	return block.Type == pkcs8Block || strings.HasSuffix(block.Type, keySuffix)
}

func readCertificate(certificatePath, keyPath string) (*Certificate, error) {
	chain, leaf, err := readChain(certificatePath)
	if err != nil {
		return nil, err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	// A leaf with a public key crypto/x509 does not know has none to match.
	matcher, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !matcher.Equal(key.Public()) {
		return nil, refusal(keyFile, ErrKeyMismatch)
	}
	return &Certificate{state: certificateState{config: newConfig(chain, key, leaf)}}, nil
}

// readFile returns the file's contents, which the caller clears. The file is opened non-blocking
// so that a named pipe opens at once on Linux, and every check after the open is on the opened
// file.
func readFile(path, file string) ([]byte, error) {
	opened, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, refusal(file, ErrTLSFileMissing)
		}
		return nil, refusal(file, ErrTLSFileUnreadable)
	}
	contents, err := readOpened(opened, file)
	closeErr := opened.Close()
	if err == nil && closeErr != nil {
		clear(contents)
		return nil, refusal(file, ErrTLSFileUnreadable)
	}
	return contents, err
}

func readOpened(opened *os.File, file string) ([]byte, error) {
	info, err := opened.Stat()
	if err != nil {
		return nil, refusal(file, ErrTLSFileUnreadable)
	}
	if !info.Mode().IsRegular() {
		return nil, refusal(file, ErrTLSFileNotRegular)
	}
	if file == keyFile && runtime.GOOS == "linux" && info.Mode().Perm()&othersReadBits != 0 {
		return nil, refusal(file, ErrKeyReadableByOthers)
	}
	// One byte more than the most, so that a longer file shows as a full buffer.
	contents := make([]byte, TLSFileMostBytes+1)
	count, err := io.ReadFull(opened, contents)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		clear(contents)
		return nil, refusal(file, ErrTLSFileUnreadable)
	}
	if count == len(contents) {
		clear(contents)
		return nil, refusal(file, ErrTLSFileNotPEM)
	}
	return contents[:count], nil
}

// readChain returns the DER of the certificate file's CERTIFICATE blocks in the file's order, and
// the first one parsed.
func readChain(path string) ([][]byte, *x509.Certificate, error) {
	contents, err := readFile(path, certificateFile)
	if err != nil {
		return nil, nil, err
	}
	defer clear(contents)
	var chain [][]byte
	var leaf *x509.Certificate
	holdsKey := false
	for rest := contents; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == certificateBlock:
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, refusal(certificateFile, ErrTLSFileNotPEM)
			}
			if leaf == nil {
				leaf = parsed
			}
			chain = append(chain, block.Bytes)
		case isKeyBlock(block):
			holdsKey = true
			clear(block.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, nil, refusal(certificateFile, ErrTLSFileNotPEM)
	}
	if holdsKey {
		return nil, nil, refusal(certificateFile, ErrCertificateHoldsKey)
	}
	return chain, leaf, nil
}

// readKey returns the key file's first private key block as a key of a type the engine serves.
func readKey(path string) (crypto.Signer, error) {
	contents, err := readFile(path, keyFile)
	if err != nil {
		return nil, err
	}
	defer clear(contents)
	var found *pem.Block
	for rest := contents; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if isKeyBlock(block) {
			defer clear(block.Bytes)
			if found == nil {
				found = block
			}
		}
	}
	if found == nil {
		return nil, refusal(keyFile, ErrTLSFileNotPEM)
	}
	if found.Type == encryptedBlock || strings.Contains(found.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, refusal(keyFile, ErrKeyPassphrase)
	}
	return parseKey(found)
}

func parseKey(block *pem.Block) (crypto.Signer, error) {
	var parsed any
	var err error
	switch block.Type {
	case pkcs8Block:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil && wrapsOtherAlgorithm(block.Bytes) {
			return nil, refusal(keyFile, ErrKeyType)
		}
	case ecBlock:
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case rsaBlock:
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, refusal(keyFile, ErrTLSFileNotPEM)
	}
	if err != nil {
		return nil, refusal(keyFile, ErrTLSFileNotPEM)
	}
	switch key := parsed.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() >= rsaLeastBits {
			return key, nil
		}
	case *ecdsa.PrivateKey:
		if key.Curve == elliptic.P256() || key.Curve == elliptic.P384() {
			return key, nil
		}
	case ed25519.PrivateKey:
		return key, nil
	}
	return nil, refusal(keyFile, ErrKeyType)
}

// wrapsOtherAlgorithm is true for a PKCS#8 key that names an algorithm other than RSA, ECDSA or
// Ed25519, such as RSA-PSS, which crypto/x509 refuses as unknown and the engine refuses as a
// key of the wrong type.
func wrapsOtherAlgorithm(der []byte) bool {
	var wrapper struct {
		Version   int
		Algorithm pkix.AlgorithmIdentifier
		Key       []byte
	}
	defer func() { clear(wrapper.Key) }()
	if _, err := asn1.Unmarshal(der, &wrapper); err != nil {
		return false
	}
	algorithm := wrapper.Algorithm.Algorithm
	return !algorithm.Equal(oidRSA) && !algorithm.Equal(oidECDSA) && !algorithm.Equal(oidEd25519)
}

// newConfig is the TLS table. TLS 1.3's suites cannot be set and are crypto/tls's own; the
// engine sets nothing else.
func newConfig(chain [][]byte, key crypto.Signer, leaf *x509.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024,
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
		},
		ClientAuth:             tls.NoClientCert,
		SessionTicketsDisabled: true,
	}
}
