// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// mostBytes is the longest file the contract's lines accept, written here so a changed constant
// in the package cannot move a test with it.
const mostBytes = 65536

// canary marks text a test puts in a file or a handshake, so an error, the log or what a caller
// receives can be searched for it.
const canary = "helios-canary-5821"

// subjectNames are the names every certificate the run makes holds, so QA's caller verifies the
// engine's certificate as a caller's client does: localhost, the loopback addresses, and the
// canary server name a row asks for.
const subjectNames = "subjectAltName=DNS:localhost,DNS:" + canary + ".test,IP:127.0.0.1,IP:::1"

// trusted is every certificate the run has made that a caller may trust: each self-signed one,
// and each intermediate that signed a leaf.
var trusted struct {
	mutex        sync.Mutex
	certificates []*x509.Certificate
}

// trust adds the certificate at path to those QA's caller trusts.
func trust(t *testing.T, path string) {
	t.Helper()
	parsed, err := x509.ParseCertificate(readBlocks(t, path)[0].Bytes)
	if err != nil {
		t.Fatalf("a fault in the test: openssl's certificate does not parse: %v", err)
	}
	trusted.mutex.Lock()
	defer trusted.mutex.Unlock()
	trusted.certificates = append(trusted.certificates, parsed)
}

// trustedPool is every certificate the run has made so far, for a caller's verification.
func trustedPool() *x509.CertPool {
	trusted.mutex.Lock()
	defer trusted.mutex.Unlock()
	pool := x509.NewCertPool()
	for _, certificate := range trusted.certificates {
		pool.AddCert(certificate)
	}
	return pool
}

// keyKind is a key as the sysop makes one with openssl genpkey, its arguments as the sysop types
// them.
type keyKind struct {
	name      string
	arguments string
}

var (
	rsa1024    = keyKind{"RSA 1024", "-algorithm RSA -pkeyopt rsa_keygen_bits:1024"}
	rsa2047    = keyKind{"RSA 2047", "-algorithm RSA -pkeyopt rsa_keygen_bits:2047"}
	rsa2048    = keyKind{"RSA 2048", "-algorithm RSA -pkeyopt rsa_keygen_bits:2048"}
	rsa4096    = keyKind{"RSA 4096", "-algorithm RSA -pkeyopt rsa_keygen_bits:4096"}
	ecdsaP256  = keyKind{"ECDSA P-256", "-algorithm EC -pkeyopt ec_paramgen_curve:P-256"}
	ecdsaP384  = keyKind{"ECDSA P-384", "-algorithm EC -pkeyopt ec_paramgen_curve:P-384"}
	ecdsaP521  = keyKind{"ECDSA P-521", "-algorithm EC -pkeyopt ec_paramgen_curve:P-521"}
	ed25519Key = keyKind{"Ed25519", "-algorithm ED25519"}
	rsaPSS2048 = keyKind{"RSA-PSS 2048", "-algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048"}

	ecdsaSecp256k1         = keyKind{"ECDSA secp256k1", "-algorithm EC -pkeyopt ec_paramgen_curve:secp256k1"}
	ecdsaSecp256k1Explicit = keyKind{
		"ECDSA secp256k1 by explicit parameters",
		"-algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -pkeyopt ec_param_enc:explicit",
	}
)

// The private key blocks openssl writes: genpkey's PKCS#8, and ecparam's SEC 1.
const (
	pkcs8KeyType = "PRIVATE KEY"
	sec1KeyType  = "EC PRIVATE KEY"
)

// tlsFiles are a certificate file and a key file, as the sysop names them.
type tlsFiles struct {
	certificate, key string
}

// openssl runs openssl in the folder given and returns what it printed; a missing openssl or a
// failed run fails the row.
func openssl(t *testing.T, folder string, arguments ...string) []byte {
	t.Helper()
	if opensslFailure != nil {
		t.Fatalf("openssl is not on this machine's PATH, and these rows need it: %v", opensslFailure)
	}
	command := exec.CommandContext(t.Context(), opensslPath, arguments...)
	command.Dir = folder
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %q: %v\n%s", arguments, err, output)
	}
	return output
}

// makeKey has openssl make a key of the kind, in a folder of its own, with only its owner able
// to read it, and returns its path.
func makeKey(t *testing.T, kind keyKind) string {
	t.Helper()
	folder := t.TempDir()
	openssl(t, folder, append(append([]string{"genpkey"}, strings.Fields(kind.arguments)...), "-out", "key.pem")...)
	path := filepath.Join(folder, "key.pem")
	setMode(t, path, 0o600)
	return path
}

// sec1Key has openssl ecparam make a key on the curve, written as an EC PRIVATE KEY block with
// the curve given by the encoding named, as the sysop makes one, and returns its path.
func sec1Key(t *testing.T, curve, encoding string) string {
	t.Helper()
	folder := t.TempDir()
	openssl(t, folder, "ecparam", "-name", curve, "-genkey", "-noout", "-param_enc", encoding, "-out", "key.pem")
	path := filepath.Join(folder, "key.pem")
	setMode(t, path, 0o600)
	return path
}

// expectKeyEncoding fails the row as a fault in the test when openssl wrote the key in another
// block, or gave its curve another way, than the row is about.
func expectKeyEncoding(t *testing.T, path, block, encoding string) {
	t.Helper()
	if got := keyBlock(t, path).Type; got != block {
		t.Fatalf("openssl wrote a %s block, and this row needs a %s block", got, block)
	}
	if text := openssl(t, filepath.Dir(path), "pkey", "-in", path, "-text", "-noout"); !strings.Contains(string(text), encoding) {
		t.Fatalf("openssl's text for the key holds no %q, which this row needs", encoding)
	}
}

// selfSigned has openssl make a self-signed certificate for the key, and returns its path.
func selfSigned(t *testing.T, keyPath string) string {
	t.Helper()
	folder := t.TempDir()
	openssl(t, folder, "req", "-x509", "-new", "-key", keyPath, "-out", "certificate.pem", "-days", "1", "-subj", "/CN=localhost", "-addext", subjectNames)
	trust(t, filepath.Join(folder, "certificate.pem"))
	return filepath.Join(folder, "certificate.pem")
}

// goodFiles is a key of the kind and a self-signed certificate for it.
func goodFiles(t *testing.T, kind keyKind) tlsFiles {
	t.Helper()
	key := makeKey(t, kind)
	return tlsFiles{certificate: selfSigned(t, key), key: key}
}

// chain is a certificate file holding a leaf certificate and the intermediate that signed it, in
// that order, the leaf's key, and each certificate's DER, as the caller must receive them.
type chain struct {
	files              tlsFiles
	intermediateKey    string
	leaf, intermediate []byte
}

// makeChain has openssl make an intermediate that may sign, and a leaf it signs, both ECDSA
// P-256.
func makeChain(t *testing.T) chain {
	t.Helper()
	folder := t.TempDir()
	intermediateKey := makeKey(t, ecdsaP256)
	openssl(t, folder, "req", "-x509", "-new", "-key", intermediateKey, "-out", "intermediate.pem", "-days", "1",
		"-subj", "/CN=Helios QA intermediate", "-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign")
	leafKey := makeKey(t, ecdsaP256)
	openssl(t, folder, "req", "-new", "-key", leafKey, "-out", "leaf.csr", "-subj", "/CN=localhost", "-addext", subjectNames)
	openssl(t, folder, "x509", "-req", "-in", "leaf.csr", "-CA", "intermediate.pem", "-CAkey", intermediateKey,
		"-set_serial", "2", "-days", "1", "-copy_extensions", "copy", "-out", "leaf.pem")
	trust(t, filepath.Join(folder, "intermediate.pem"))
	leaf := certificateDER(t, filepath.Join(folder, "leaf.pem"))
	intermediate := certificateDER(t, filepath.Join(folder, "intermediate.pem"))
	path := writeBlocks(t, certificateBlock(leaf), certificateBlock(intermediate))
	return chain{files: tlsFiles{certificate: path, key: leafKey}, intermediateKey: intermediateKey, leaf: leaf, intermediate: intermediate}
}

// certificateDER reads the one CERTIFICATE block of a file openssl wrote.
func certificateDER(t *testing.T, path string) []byte {
	t.Helper()
	blocks := readBlocks(t, path)
	if len(blocks) != 1 || blocks[0].Type != "CERTIFICATE" {
		t.Fatalf("%s holds %d blocks, want one certificate", path, len(blocks))
	}
	return blocks[0].Bytes
}

func certificateBlock(der []byte) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: der}
}

// readBlocks reads every PEM block of a file the test made.
func readBlocks(t *testing.T, path string) []*pem.Block {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var blocks []*pem.Block
	for {
		var block *pem.Block
		block, text = pem.Decode(text)
		if block == nil {
			return blocks
		}
		blocks = append(blocks, block)
	}
}

// writeBlocks writes the blocks, in order, to a new file only its owner may read, and returns its
// path.
func writeBlocks(t *testing.T, blocks ...*pem.Block) string {
	t.Helper()
	var text []byte
	for _, block := range blocks {
		text = append(text, pem.EncodeToMemory(block)...)
	}
	return writeFile(t, text)
}

// writeFile writes the bytes to a new file only its owner may read, and returns its path.
func writeFile(t *testing.T, text []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file.pem")
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	setMode(t, path, 0o600)
	return path
}

// readFile reads a file the test made.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// setMode gives a file the mode its row is about.
func setMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setting %s to %#o: %v", path, mode, err)
	}
}

// encrypted is the key protected by the passphrase secret: as a PKCS#8 ENCRYPTED PRIVATE KEY
// block, or, with legacy, as an RSA PRIVATE KEY block with the old PEM header.
func encrypted(t *testing.T, keyPath string, legacy bool) string {
	t.Helper()
	folder := t.TempDir()
	if legacy {
		openssl(t, folder, "rsa", "-in", keyPath, "-aes256", "-traditional", "-passout", "pass:secret", "-out", "key.pem")
	} else {
		openssl(t, folder, "pkcs8", "-topk8", "-in", keyPath, "-passout", "pass:secret", "-out", "key.pem")
	}
	path := filepath.Join(folder, "key.pem")
	setMode(t, path, 0o600)
	return path
}

// randomText is printable text that holds no PEM boundary, for padding outside the blocks.
func randomText(t *testing.T, size int) []byte {
	t.Helper()
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
	for index := range raw {
		raw[index] = letters[int(raw[index])%len(letters)]
	}
	return raw
}

// paddedTo is a copy of the file, with random text before its blocks so it is exactly size bytes
// long: text outside the blocks, which PEM allows.
func paddedTo(t *testing.T, path string, size int) string {
	t.Helper()
	text := readFile(t, path)
	if len(text)+1 >= size {
		t.Fatalf("%s is already %d bytes, too long to pad to %d", path, len(text), size)
	}
	padding := append(randomText(t, size-len(text)-1), '\n')
	padded := append(padding, text...)
	if len(padded) != size {
		t.Fatalf("the padded file is %d bytes, want %d", len(padded), size)
	}
	return writeFile(t, padded)
}

// bodies is the base64 text of every block of the files, with no line breaks: what an error's
// text must hold no 8 characters in a row of.
func bodies(t *testing.T, paths ...string) []string {
	t.Helper()
	var parts []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		var body strings.Builder
		inside := false
		for line := range strings.SplitSeq(string(readFile(t, path)), "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "-----BEGIN"):
				inside = true
			case strings.HasPrefix(line, "-----END"):
				inside = false
				parts = append(parts, body.String())
				body.Reset()
			case inside && !strings.Contains(line, ":"):
				body.WriteString(line)
			}
		}
	}
	return parts
}

// holdsPart is whether text holds 8 characters in a row of any of the parts.
func holdsPart(text string, parts []string) bool {
	for _, part := range parts {
		for start := 0; start+8 <= len(part); start++ {
			if strings.Contains(text, part[start:start+8]) {
				return true
			}
		}
	}
	return false
}

// joinFiles is the files' bytes one after the other, written to a new file.
func joinFiles(t *testing.T, paths ...string) string {
	t.Helper()
	var text []byte
	for _, path := range paths {
		text = append(text, readFile(t, path)...)
	}
	return writeFile(t, text)
}

// withText is the file with text before and after its blocks.
func withText(t *testing.T, path string) string {
	t.Helper()
	return writeFile(t, bytes.Join([][]byte{[]byte("text before the blocks\n"), readFile(t, path), []byte("text after them\n")}, nil))
}
