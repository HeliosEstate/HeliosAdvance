// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// machineKeyFlag looks for the key among the machine's keys, not the account's.
	machineKeyFlag = 0x20
	// silentFlag makes a key store call fail at once where it would ask for a prompt; a service has
	// no desktop to show one on.
	silentFlag = 0x40
	// oaepPadFlag says the padding information handed to the unwrap is OAEP's.
	oaepPadFlag = 0x4
	// bufferTooSmall is the key store's answer to an unwrap longer than the buffer it was given;
	// tpmBufferTooSmall is the TPM's own code for the same case.
	bufferTooSmall    = 0x80090028
	tpmBufferTooSmall = 0x80290406
	// statusBits is what a status keeps: the calling convention leaves the register's upper half
	// unspecified.
	statusBits = 0xffffffff

	// descriptorMostBytes is the most a descriptor holding an owner and an access list takes: its
	// 20-byte header, an account of at most 68 bytes, and an access list of at most 65,535 bytes,
	// whose size is a 16-bit field.
	descriptorMostBytes = 20 + 68 + 65535
)

var (
	storeLibrary = windows.NewLazySystemDLL("ncrypt.dll")
	openStore    = storeLibrary.NewProc("NCryptOpenStorageProvider")
	openKey      = storeLibrary.NewProc("NCryptOpenKey")
	getProperty  = storeLibrary.NewProc("NCryptGetProperty")
	decrypt      = storeLibrary.NewProc("NCryptDecrypt")
	freeObject   = storeLibrary.NewProc("NCryptFreeObject")
)

// oaepPadding is the key store's BCRYPT_OAEP_PADDING_INFO, laid out as Windows lays it out.
type oaepPadding struct {
	algorithm  *uint16
	label      *byte
	labelBytes uint32
}

// storeName is the key store a key holder names.
func storeName(keyHolder byte) string {
	if keyHolder == KeyHolderTPM {
		return "Microsoft Platform Crypto Provider"
	}
	return "Microsoft Software Key Storage Provider"
}

// storeHeaderIsOurs accepts the TPM and the software key store, whose sealed key has its one
// length and a name in its form.
func storeHeaderIsOurs(sealed []byte) bool {
	if sealed[10] != KeyHolderTPM && sealed[10] != KeyHolderSoftwareKeyStore {
		return false
	}
	if int(binary.BigEndian.Uint16(sealed[11:13])) != SealedKeyBytes ||
		len(sealed) < HeaderBytes+SealedKeyBytes+NonceBytes+TagBytes {
		return false
	}
	name := sealed[HeaderBytes : HeaderBytes+KeyNameBytes]
	if string(name[:len(KeyNamePrefix)]) != KeyNamePrefix {
		return false
	}
	for _, digit := range name[len(KeyNamePrefix):] {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

// takeKey gives the key from the key holder the header names; the header check lets no other
// through.
func takeKey(root *os.Root, sealed, buffer []byte) ([]byte, error) {
	if sealed[10] == KeyHolderKeyFile {
		return readKeyFile(root, buffer)
	}
	return unwrapKey(sealed[10], sealed[HeaderBytes:HeaderBytes+SealedKeyBytes], buffer)
}

// unwrapKey opens the key store and the key the sealed key names, judges who has access to it, and
// unwraps the bootstrap file's key under it into buffer. A handle is freed once, after its open
// succeeded.
func unwrapKey(keyHolder byte, sealedKey, buffer []byte) (key []byte, err error) {
	name := storeName(keyHolder)
	refuse := func(answer error) error {
		return fmt.Errorf("%w: %s: %w", ErrKeyStore, name, answer)
	}
	for _, procedure := range []*windows.LazyProc{openStore, openKey, getProperty, decrypt, freeObject} {
		if err := procedure.Find(); err != nil {
			return nil, refuse(err)
		}
	}
	storeText, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, refuse(err)
	}
	keyText, err := windows.UTF16PtrFromString(string(sealedKey[:KeyNameBytes]))
	if err != nil {
		return nil, refuse(err)
	}
	var store, handle uintptr
	if status := call(openStore, uintptr(unsafe.Pointer(&store)),
		uintptr(unsafe.Pointer(storeText)), 0); status != 0 {
		return nil, refuse(windows.Errno(status))
	}
	defer func() { err = freed(store, err, refuse) }()
	if status := call(openKey, store, uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(keyText)), 0, machineKeyFlag|silentFlag); status != 0 {
		return nil, refuse(windows.Errno(status))
	}
	defer func() { err = freed(handle, err, refuse) }()
	if err := judgeKey(handle); err != nil {
		return nil, err
	}
	return unwrap(handle, sealedKey[KeyNameBytes:], buffer, refuse)
}

// freed adds a failed free to what the call already gives only when nothing before it failed, as
// a failed close of a file is a refusal.
func freed(handle uintptr, err error, refuse func(error) error) error {
	if status := call(freeObject, handle); status != 0 && err == nil {
		return refuse(windows.Errno(status))
	}
	return err
}

// judgeKey reads the owner and access list from the key's own handle, never by its name again.
func judgeKey(handle uintptr) error {
	property, err := windows.UTF16PtrFromString("Security Descr")
	if err != nil {
		return ErrKeyStorePermissions
	}
	buffer := make([]byte, descriptorMostBytes)
	var length uint32
	status := call(getProperty, handle, uintptr(unsafe.Pointer(property)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&length)),
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|silentFlag)
	if status != 0 || int(length) > len(buffer) {
		return ErrKeyStorePermissions
	}
	// The bytes are the key store's own, self-relative, and judged by Windows' own accessors.
	descriptor := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buffer[0]))
	if !descriptor.IsValid() {
		return ErrKeyStorePermissions
	}
	return judgeAccess(descriptor, ErrKeyStorePermissions, ErrKeyStoreReachable)
}

// unwrap decrypts into the whole buffer, one byte longer than the key, so the key store itself
// refuses a longer result.
func unwrap(handle uintptr, wrapped, buffer []byte, refuse func(error) error) ([]byte, error) {
	algorithm, err := windows.UTF16PtrFromString("SHA256")
	if err != nil {
		return nil, refuse(err)
	}
	padding := oaepPadding{algorithm: algorithm}
	var length uint32
	status := call(decrypt, handle, uintptr(unsafe.Pointer(&wrapped[0])), uintptr(len(wrapped)),
		uintptr(unsafe.Pointer(&padding)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&length)), oaepPadFlag|silentFlag)
	if status == bufferTooSmall || status == tpmBufferTooSmall {
		return nil, ErrUnwrap
	}
	if status != 0 {
		return nil, refuse(windows.Errno(status))
	}
	if length != KeyBytes || bytes.Equal(buffer[:KeyBytes], make([]byte, KeyBytes)) {
		return nil, ErrUnwrap
	}
	return buffer[:KeyBytes], nil
}

// call runs a key store procedure with its arguments and gives its status. The pointers converted
// in its arguments stay alive and in place until it returns. The last error the call also gives is
// not the key store's answer, which is the status.
//
//go:uintptrescapes
//nolint:errcheck // the third result is the thread's last error, not the key store's answer
func call(procedure *windows.LazyProc, arguments ...uintptr) uintptr {
	status, _, _ := procedure.Call(arguments...)
	return status & statusBits
}
