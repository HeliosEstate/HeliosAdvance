// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package telnets_test

import (
	"encoding/pem"
	"errors"
	"path/filepath"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/telnets"
)

// refusal calls ReadCertificate on the files, which must refuse them, and returns its error.
func refusal(t *testing.T, files tlsFiles) error {
	t.Helper()
	certificate, err := telnets.ReadCertificate(files.certificate, files.key)
	if err == nil || certificate != nil {
		t.Fatalf("ReadCertificate gave %v and %v, want a refusal", certificate, err)
	}
	return err
}

// refusedWith checks ReadCertificate refuses the files with the error given, and returns the
// error, for a row that reads its text.
func refusedWith(t *testing.T, files tlsFiles, want error) error {
	t.Helper()
	err := refusal(t, files)
	if !errors.Is(err, want) {
		t.Fatalf("ReadCertificate gave %v, want %v", err, want)
	}
	return err
}

// expectRefusal checks ReadCertificate refuses the files with the error given.
func expectRefusal(t *testing.T, files tlsFiles, want error) {
	t.Helper()
	_ = refusedWith(t, files, want)
}

// missingPath is a path in a folder of its own at which no file is.
func missingPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent.pem")
}

// keyBlock is the first block of a key file openssl wrote.
func keyBlock(t *testing.T, path string) *pem.Block {
	t.Helper()
	return readBlocks(t, path)[0]
}

// notCertificate is a CERTIFICATE block that holds no X.509 certificate.
func notCertificate() *pem.Block {
	return certificateBlock([]byte(canary + " is not a certificate"))
}

// curveParameters is an EC PARAMETERS block naming P-256, as openssl ecparam writes one.
func curveParameters() *pem.Block {
	return &pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}}
}

func TestReadCertificate(t *testing.T) {
	t.Parallel()

	t.Run("ReadCertificate shall check the certificate file and then the key file, in the order of these lines, and return the first refusal that applies.", func(t *testing.T) {
		t.Parallel()
		t.Run("a missing certificate file and a missing key file: the certificate file's ErrTLSFileMissing", func(t *testing.T) {
			t.Parallel()
			good := goodFiles(t, ecdsaP256)
			alone := refusedWith(t, tlsFiles{certificate: missingPath(t), key: good.key}, telnets.ErrTLSFileMissing)
			both := refusedWith(t, tlsFiles{certificate: missingPath(t), key: missingPath(t)}, telnets.ErrTLSFileMissing)
			keyOnly := refusedWith(t, tlsFiles{certificate: good.certificate, key: missingPath(t)}, telnets.ErrTLSFileMissing)
			if both.Error() != alone.Error() || both.Error() == keyOnly.Error() {
				t.Fatalf("both files missing gave %q; the certificate file alone %q, the key file alone %q", both, alone, keyOnly)
			}
		})
		t.Run("a folder as the certificate file and a missing key file: ErrTLSFileNotRegular", func(t *testing.T) {
			t.Parallel()
			expectRefusal(t, tlsFiles{certificate: t.TempDir(), key: missingPath(t)}, telnets.ErrTLSFileNotRegular)
		})
		t.Run("an RSA 1024 key that does not match the certificate: ErrKeyType", func(t *testing.T) {
			t.Parallel()
			expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: makeKey(t, rsa1024)}, telnets.ErrKeyType)
		})
		t.Run("a CERTIFICATE block that is not a certificate beside a key block in the certificate file: ErrTLSFileNotPEM", func(t *testing.T) {
			t.Parallel()
			good := goodFiles(t, ecdsaP256)
			certificate := writeBlocks(t, notCertificate(), keyBlock(t, good.key))
			expectRefusal(t, tlsFiles{certificate: certificate, key: good.key}, telnets.ErrTLSFileNotPEM)
		})
		t.Run("a key in the certificate file and the key file missing: ErrCertificateHoldsKey", func(t *testing.T) {
			t.Parallel()
			good := goodFiles(t, ecdsaP256)
			expectRefusal(t, tlsFiles{certificate: joinFiles(t, good.certificate, good.key), key: missingPath(t)}, telnets.ErrCertificateHoldsKey)
		})
	})

	t.Run("If no file is at the path, then ReadCertificate shall return ErrTLSFileMissing.", func(t *testing.T) {
		t.Parallel()
		t.Run("the certificate file missing: ErrTLSFileMissing", func(t *testing.T) {
			t.Parallel()
			expectRefusal(t, tlsFiles{certificate: missingPath(t), key: goodFiles(t, ecdsaP256).key}, telnets.ErrTLSFileMissing)
		})
		t.Run("the key file missing: ErrTLSFileMissing", func(t *testing.T) {
			t.Parallel()
			expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: missingPath(t)}, telnets.ErrTLSFileMissing)
		})
	})

	t.Run("If the opened file is not a regular file, such as a folder or a named pipe, then ReadCertificate shall return ErrTLSFileNotRegular, without reading it and without waiting on it, its open included.", func(t *testing.T) {
		t.Parallel()
		t.Run("a folder as the certificate file: ErrTLSFileNotRegular", func(t *testing.T) {
			t.Parallel()
			expectRefusal(t, tlsFiles{certificate: t.TempDir(), key: goodFiles(t, ecdsaP256).key}, telnets.ErrTLSFileNotRegular)
		})
		t.Run("a folder as the key file: ErrTLSFileNotRegular", func(t *testing.T) {
			t.Parallel()
			expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: t.TempDir()}, telnets.ErrTLSFileNotRegular)
		})
	})

	t.Run("If the file is longer than TLSFileMostBytes or holds no PEM block, then ReadCertificate shall return ErrTLSFileNotPEM.", func(t *testing.T) {
		t.Parallel()
		for _, which := range []string{certificateFile, keyFile} {
			t.Run("the "+which+" file one byte over 65,536, a good file padded with text: ErrTLSFileNotPEM", func(t *testing.T) {
				t.Parallel()
				files := goodFiles(t, ecdsaP256)
				expectRefusal(t, replaced(t, files, which, paddedTo(t, chosen(files, which), mostBytes+1)), telnets.ErrTLSFileNotPEM)
			})
			t.Run("the "+which+" file empty: ErrTLSFileNotPEM", func(t *testing.T) {
				t.Parallel()
				expectRefusal(t, replaced(t, goodFiles(t, ecdsaP256), which, writeFile(t, nil)), telnets.ErrTLSFileNotPEM)
			})
			t.Run("the "+which+" file text alone: ErrTLSFileNotPEM", func(t *testing.T) {
				t.Parallel()
				expectRefusal(t, replaced(t, goodFiles(t, ecdsaP256), which, writeFile(t, []byte(canary+" is not PEM\n"))), telnets.ErrTLSFileNotPEM)
			})
			t.Run("the edge: the "+which+" file exactly 65,536 bytes, a good file padded with text, is read", func(t *testing.T) {
				t.Parallel()
				files := goodFiles(t, ecdsaP256)
				readCertificate(t, replaced(t, files, which, paddedTo(t, chosen(files, which), mostBytes)))
			})
		}
	})

	t.Run("If the certificate file holds no CERTIFICATE block, or a CERTIFICATE block that does not hold an X.509 certificate, the chain's later blocks included, then ReadCertificate shall return ErrTLSFileNotPEM.", func(t *testing.T) {
		t.Parallel()
		t.Run("the first CERTIFICATE block not a certificate, before a good one: ErrTLSFileNotPEM", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			certificate := writeBlocks(t, notCertificate(), readBlocks(t, files.certificate)[0])
			expectRefusal(t, tlsFiles{certificate: certificate, key: files.key}, telnets.ErrTLSFileNotPEM)
		})
		t.Run("the second CERTIFICATE block not a certificate, after a good one: ErrTLSFileNotPEM", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			certificate := writeBlocks(t, readBlocks(t, files.certificate)[0], notCertificate())
			expectRefusal(t, tlsFiles{certificate: certificate, key: files.key}, telnets.ErrTLSFileNotPEM)
		})
		t.Run("a third CERTIFICATE block not a certificate, after a good chain of two: ErrTLSFileNotPEM", func(t *testing.T) {
			t.Parallel()
			made := makeChain(t)
			certificate := writeBlocks(t, certificateBlock(made.leaf), certificateBlock(made.intermediate), notCertificate())
			expectRefusal(t, tlsFiles{certificate: certificate, key: made.files.key}, telnets.ErrTLSFileNotPEM)
		})
		t.Run("a certificate file with blocks of other types and no CERTIFICATE block: ErrTLSFileNotPEM", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			certificate := writeBlocks(t, curveParameters(), &pem.Block{Type: "X509 CRL", Bytes: readBlocks(t, files.certificate)[0].Bytes})
			expectRefusal(t, tlsFiles{certificate: certificate, key: files.key}, telnets.ErrTLSFileNotPEM)
		})
		t.Run("the edge: a good chain of two, the leaf matching the key, is read", func(t *testing.T) {
			t.Parallel()
			readCertificate(t, makeChain(t).files)
		})
	})

	t.Run("If the certificate file holds a private key block, then ReadCertificate shall return ErrCertificateHoldsKey.", func(t *testing.T) {
		t.Parallel()
		blocks := []struct {
			name  string
			block func(t *testing.T, files tlsFiles) *pem.Block
		}{
			{pkcs8KeyType, func(t *testing.T, files tlsFiles) *pem.Block { t.Helper(); return keyBlock(t, files.key) }},
			{sec1KeyType, func(t *testing.T, _ tlsFiles) *pem.Block {
				t.Helper()
				folder := t.TempDir()
				openssl(t, folder, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "key.pem")
				return keyBlock(t, filepath.Join(folder, "key.pem"))
			}},
			{"RSA PRIVATE KEY", func(t *testing.T, _ tlsFiles) *pem.Block {
				t.Helper()
				folder := t.TempDir()
				openssl(t, folder, "rsa", "-in", makeKey(t, rsa2048), "-traditional", "-out", "key.pem")
				return keyBlock(t, filepath.Join(folder, "key.pem"))
			}},
			{"ENCRYPTED PRIVATE KEY", func(t *testing.T, files tlsFiles) *pem.Block {
				t.Helper()
				return keyBlock(t, encrypted(t, files.key, false))
			}},
		}
		for _, kind := range blocks {
			t.Run("a "+kind.name+" block after the certificate: ErrCertificateHoldsKey", func(t *testing.T) {
				t.Parallel()
				files := goodFiles(t, ecdsaP256)
				block := kind.block(t, files)
				if block.Type != kind.name {
					t.Fatalf("a fault in the test: openssl wrote a %s block, want %s", block.Type, kind.name)
				}
				certificate := writeBlocks(t, readBlocks(t, files.certificate)[0], block)
				expectRefusal(t, tlsFiles{certificate: certificate, key: files.key}, telnets.ErrCertificateHoldsKey)
			})
		}
		t.Run("a PRIVATE KEY block before the certificate: ErrCertificateHoldsKey", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			expectRefusal(t, tlsFiles{certificate: joinFiles(t, files.key, files.certificate), key: files.key}, telnets.ErrCertificateHoldsKey)
		})
		t.Run("the edge: an EC PARAMETERS block and text around the blocks are skipped, and the files read", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			parameters := curveParameters()
			certificate := withText(t, writeBlocks(t, parameters, readBlocks(t, files.certificate)[0]))
			readCertificate(t, tlsFiles{certificate: certificate, key: withText(t, files.key)})
		})
	})

	t.Run("If the key file holds no private key block, then ReadCertificate shall return ErrTLSFileNotPEM.", func(t *testing.T) {
		t.Parallel()
		t.Run("a key file holding a copy of the certificate alone, only its owner able to read it: ErrTLSFileNotPEM", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			expectRefusal(t, tlsFiles{certificate: files.certificate, key: writeFile(t, readFile(t, files.certificate))}, telnets.ErrTLSFileNotPEM)
		})
		t.Run("the edge: an EC PARAMETERS block before an EC PRIVATE KEY block, as openssl ecparam writes them: read", func(t *testing.T) {
			t.Parallel()
			folder := t.TempDir()
			openssl(t, folder, "ecparam", "-name", "prime256v1", "-genkey", "-out", "key.pem")
			key := filepath.Join(folder, "key.pem")
			setMode(t, key, 0o600)
			if blocks := readBlocks(t, key); len(blocks) != 2 || blocks[0].Type != "EC PARAMETERS" {
				t.Fatalf("a fault in the test: openssl ecparam wrote %d blocks", len(blocks))
			}
			readCertificate(t, tlsFiles{certificate: selfSigned(t, key), key: key})
		})
	})

	t.Run("If the key is protected by a passphrase, then ReadCertificate shall return ErrKeyPassphrase.", func(t *testing.T) {
		t.Parallel()
		t.Run("an ECDSA P-256 key as a PKCS#8 ENCRYPTED PRIVATE KEY block: ErrKeyPassphrase", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			expectRefusal(t, tlsFiles{certificate: files.certificate, key: encrypted(t, files.key, false)}, telnets.ErrKeyPassphrase)
		})
		t.Run("an RSA 2048 key with the old PEM header Proc-Type 4,ENCRYPTED: ErrKeyPassphrase", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, rsa2048)
			expectRefusal(t, tlsFiles{certificate: files.certificate, key: encrypted(t, files.key, true)}, telnets.ErrKeyPassphrase)
		})
	})

	t.Run("If the key's block does not hold a private key, then ReadCertificate shall return ErrTLSFileNotPEM.", func(t *testing.T) {
		t.Parallel()
		t.Run("a PRIVATE KEY block of text: ErrTLSFileNotPEM", func(t *testing.T) {
			t.Parallel()
			files := goodFiles(t, ecdsaP256)
			key := writeBlocks(t, &pem.Block{Type: pkcs8KeyType, Bytes: []byte(canary + " is not a key")})
			expectRefusal(t, tlsFiles{certificate: files.certificate, key: key}, telnets.ErrTLSFileNotPEM)
		})
	})

	t.Run("If the key is not RSA of 2048 bits or more, ECDSA P-256 or P-384, or Ed25519, then ReadCertificate shall return ErrKeyType.", func(t *testing.T) {
		t.Parallel()
		for _, kind := range []keyKind{rsa1024, rsa2047, ecdsaP521, rsaPSS2048} {
			t.Run(kind.name+" with its own certificate: ErrKeyType", func(t *testing.T) {
				t.Parallel()
				expectRefusal(t, goodFiles(t, kind), telnets.ErrKeyType)
			})
		}
		// crypto/x509 reads none of these keys, so the engine must tell them from a damaged file.
		for _, key := range []struct {
			name, block, encoding string
			make                  func(t *testing.T) string
		}{
			{"ECDSA secp256k1, by its curve's name, in an EC PRIVATE KEY block", sec1KeyType, "ASN1 OID: secp256k1",
				func(t *testing.T) string { t.Helper(); return sec1Key(t, "secp256k1", "named_curve") }},
			{"ECDSA secp256k1, by explicit parameters, in an EC PRIVATE KEY block", sec1KeyType, "Field Type: prime-field",
				func(t *testing.T) string { t.Helper(); return sec1Key(t, "secp256k1", "explicit") }},
			{"ECDSA secp256k1, by its curve's name, in a PRIVATE KEY block", pkcs8KeyType, "ASN1 OID: secp256k1",
				func(t *testing.T) string { t.Helper(); return makeKey(t, ecdsaSecp256k1) }},
			{"ECDSA secp256k1, by explicit parameters, in a PRIVATE KEY block", pkcs8KeyType, "Field Type: prime-field",
				func(t *testing.T) string { t.Helper(); return makeKey(t, ecdsaSecp256k1Explicit) }},
		} {
			t.Run(key.name+", with an ECDSA P-256 certificate: ErrKeyType", func(t *testing.T) {
				t.Parallel()
				path := key.make(t)
				expectKeyEncoding(t, path, key.block, key.encoding)
				expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: path}, telnets.ErrKeyType)
			})
		}
		for _, kind := range []keyKind{rsa2048, rsa4096, ecdsaP256, ecdsaP384, ed25519Key} {
			t.Run("the edge: "+kind.name+" with its own certificate is read", func(t *testing.T) {
				t.Parallel()
				readCertificate(t, goodFiles(t, kind))
			})
		}
	})

	t.Run("If the key does not match the certificate, the first CERTIFICATE block's, then ReadCertificate shall return ErrKeyMismatch.", func(t *testing.T) {
		t.Parallel()
		t.Run("another ECDSA P-256 key: ErrKeyMismatch", func(t *testing.T) {
			t.Parallel()
			expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: makeKey(t, ecdsaP256)}, telnets.ErrKeyMismatch)
		})
		t.Run("an RSA 2048 key against an ECDSA certificate: ErrKeyMismatch", func(t *testing.T) {
			t.Parallel()
			expectRefusal(t, tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: makeKey(t, rsa2048)}, telnets.ErrKeyMismatch)
		})
		t.Run("the key of the chain's second certificate alone: ErrKeyMismatch", func(t *testing.T) {
			t.Parallel()
			made := makeChain(t)
			expectRefusal(t, tlsFiles{certificate: made.files.certificate, key: made.intermediateKey}, telnets.ErrKeyMismatch)
		})
	})

	t.Run("ReadCertificate shall return an error whose text names the file it is about, the certificate file or the key file, and holds no part of either file's contents.", func(t *testing.T) {
		t.Parallel()
		both := []struct {
			name string
			want error
			bad  func(t *testing.T, files tlsFiles, which string) string
		}{
			{"missing", telnets.ErrTLSFileMissing, func(t *testing.T, _ tlsFiles, _ string) string { t.Helper(); return missingPath(t) }},
			{"a folder", telnets.ErrTLSFileNotRegular, func(t *testing.T, _ tlsFiles, _ string) string { t.Helper(); return t.TempDir() }},
			{"text alone", telnets.ErrTLSFileNotPEM, func(t *testing.T, _ tlsFiles, _ string) string {
				t.Helper()
				return writeFile(t, []byte(canary+" is not PEM\n"))
			}},
			{"one byte over 65,536", telnets.ErrTLSFileNotPEM, func(t *testing.T, files tlsFiles, which string) string {
				t.Helper()
				return paddedTo(t, chosen(files, which), mostBytes+1)
			}},
		}
		for _, refused := range both {
			t.Run(refused.name+", as either file: the certificate file's text differs from the key file's, and neither holds 8 characters in a row of the files", func(t *testing.T) {
				t.Parallel()
				files := goodFiles(t, ecdsaP256)
				certificateBad := replaced(t, files, certificateFile, refused.bad(t, files, certificateFile))
				keyBad := replaced(t, files, keyFile, refused.bad(t, files, keyFile))
				certificateErr := refusedWith(t, certificateBad, refused.want)
				keyErr := refusedWith(t, keyBad, refused.want)
				if certificateErr.Error() == keyErr.Error() {
					t.Fatalf("the certificate file and the key file gave the same text, %q", certificateErr)
				}
				parts := append(bodies(t, files.certificate, files.key, certificateBad.certificate, keyBad.key), canary)
				for _, err := range []error{certificateErr, keyErr} {
					if holdsPart(err.Error(), parts) {
						t.Fatalf("the error's text %q holds part of a file", err)
					}
				}
			})
		}
		one := []struct {
			name  string
			want  error
			files func(t *testing.T) tlsFiles
		}{
			{"a key in the certificate file", telnets.ErrCertificateHoldsKey, func(t *testing.T) tlsFiles {
				t.Helper()
				files := goodFiles(t, ecdsaP256)
				return tlsFiles{certificate: joinFiles(t, files.certificate, files.key), key: files.key}
			}},
			{"a key with a passphrase", telnets.ErrKeyPassphrase, func(t *testing.T) tlsFiles {
				t.Helper()
				files := goodFiles(t, ecdsaP256)
				return tlsFiles{certificate: files.certificate, key: encrypted(t, files.key, false)}
			}},
			{"an RSA 1024 key", telnets.ErrKeyType, func(t *testing.T) tlsFiles { t.Helper(); return goodFiles(t, rsa1024) }},
			{"a key that does not match", telnets.ErrKeyMismatch, func(t *testing.T) tlsFiles {
				t.Helper()
				return tlsFiles{certificate: goodFiles(t, ecdsaP256).certificate, key: makeKey(t, ecdsaP256)}
			}},
			{"a CERTIFICATE block that is not a certificate", telnets.ErrTLSFileNotPEM, func(t *testing.T) tlsFiles {
				t.Helper()
				files := goodFiles(t, ecdsaP256)
				return tlsFiles{certificate: writeBlocks(t, readBlocks(t, files.certificate)[0], notCertificate()), key: files.key}
			}},
		}
		for _, refused := range one {
			t.Run(refused.name+": the text holds no 8 characters in a row of either file", func(t *testing.T) {
				t.Parallel()
				files := refused.files(t)
				err := refusedWith(t, files, refused.want)
				if holdsPart(err.Error(), append(bodies(t, files.certificate, files.key), canary)) {
					t.Fatalf("the error's text %q holds part of a file", err)
				}
			})
		}
	})
}

// The two values of which, as the rows name the files.
const (
	certificateFile = "certificate"
	keyFile         = "key"
)

// chosen is the path of the file named by which, certificateFile or keyFile.
func chosen(files tlsFiles, which string) string {
	if which == certificateFile {
		return files.certificate
	}
	return files.key
}

// replaced is the files with the one named by which, certificateFile or keyFile, at path instead.
func replaced(t *testing.T, files tlsFiles, which, path string) tlsFiles {
	t.Helper()
	if which == certificateFile {
		files.certificate = path
	} else {
		files.key = path
	}
	return files
}
