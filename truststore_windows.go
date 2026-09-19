// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	FirefoxProfiles     = []string{os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"}
	CertutilInstallHelp = "" // certutil unsupported on Windows
	NSSBrowsers         = "Firefox"
)

// golang.org/x/sys/windows provides typed wrappers for the crypt32 calls used
// here, so a certificate context stays a *windows.CertContext for its whole
// life. The hand-rolled LazyProc version took the uintptr that Call returns and
// converted it straight back to a pointer -- the "possible misuse of
// unsafe.Pointer" go vet reported, and the only vet finding this repository had.
//
// CertAddEncodedCertificateToStore is the exception: x/sys has no wrapper for
// it, so it keeps a LazyProc below. That direction is fine. Passing a pointer
// INTO a syscall as an inline uintptr(unsafe.Pointer(...)) argument is the form
// the unsafe rules explicitly permit; it was only the reverse -- a uintptr
// coming back out and being turned into a pointer -- that was unsound.
var (
	modcrypt32                           = syscall.NewLazyDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
)

func (m *mkcert) installPlatform() bool {
	// Load cert
	cert, err := os.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")
	// Decode PEM
	if certBlock, _ := pem.Decode(cert); certBlock == nil || certBlock.Type != "CERTIFICATE" {
		fatalIfErr(fmt.Errorf("invalid PEM data"), "decode pem")
	} else {
		cert = certBlock.Bytes
	}
	// Open root store
	store, err := openWindowsRootStore()
	fatalIfErr(err, "open root store")
	defer store.close()
	// Add cert
	fatalIfErr(store.addCert(cert), "add cert")
	return true
}

func (m *mkcert) uninstallPlatform() bool {
	// We'll just remove all certs with the same serial number
	// Open root store
	store, err := openWindowsRootStore()
	fatalIfErr(err, "open root store")
	defer store.close()
	// Do the deletion
	deletedAny, err := store.deleteCertsWithSerial(m.caCert.SerialNumber)
	if err == nil && !deletedAny {
		err = fmt.Errorf("no certs found")
	}
	fatalIfErr(err, "delete cert")
	return true
}

type windowsRootStore windows.Handle

func openWindowsRootStore() (windowsRootStore, error) {
	rootStr, err := syscall.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenSystemStore(0, rootStr)
	if err != nil {
		return 0, fmt.Errorf("failed to open windows root store: %v", err)
	}
	return windowsRootStore(store), nil
}

func (w windowsRootStore) close() error {
	if err := windows.CertCloseStore(windows.Handle(w), 0); err != nil {
		return fmt.Errorf("failed to close windows root store: %v", err)
	}
	return nil
}

func (w windowsRootStore) addCert(cert []byte) error {
	// TODO: ok to always overwrite?
	ret, _, err := procCertAddEncodedCertificateToStore.Call(
		uintptr(w), // HCERTSTORE hCertStore
		uintptr(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING), // DWORD dwCertEncodingType
		uintptr(unsafe.Pointer(&cert[0])),                              // const BYTE *pbCertEncoded
		uintptr(len(cert)),                                             // DWORD cbCertEncoded
		3,                                                              // DWORD dwAddDisposition (CERT_STORE_ADD_REPLACE_EXISTING is 3)
		0,                                                              // PCCERT_CONTEXT *ppCertContext
	)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("failed adding cert: %v", err)
}

// certBytes returns a certificate context's DER.
//
// This used to be (*[1 << 20]byte)(unsafe.Pointer(c.EncodedCert))[:c.Length],
// which silently truncates any certificate larger than a megabyte and is
// exactly the construct unsafe.Slice was added to replace.
func certBytes(c *windows.CertContext) []byte {
	return unsafe.Slice(c.EncodedCert, c.Length)
}

// forEachCert calls f for every certificate in the store, stopping early if f
// returns false.
//
// Enumeration lives apart from deletion so it can be exercised by tests without
// going anywhere near the delete path -- walking the caller's real root store
// is safe, removing things from it is not.
func (w windowsRootStore) forEachCert(f func(*windows.CertContext) bool) error {
	var cert *windows.CertContext
	for {
		// CertEnumCertificatesInStore frees the context passed to it and
		// returns the next one, so the previous pointer must not be reused.
		next, err := windows.CertEnumCertificatesInStore(windows.Handle(w), cert)
		if next == nil {
			if err == nil || err == syscall.Errno(windows.CRYPT_E_NOT_FOUND) {
				return nil // walked the whole store
			}
			return fmt.Errorf("failed enumerating certs: %v", err)
		}
		cert = next
		if !f(cert) {
			// Nothing will call Enum again to free this one for us.
			if err := windows.CertFreeCertificateContext(cert); err != nil {
				return fmt.Errorf("failed freeing cert context: %v", err)
			}
			return nil
		}
	}
}

func (w windowsRootStore) deleteCertsWithSerial(serial *big.Int) (bool, error) {
	deletedAny := false
	var deleteErr error

	err := w.forEachCert(func(cert *windows.CertContext) bool {
		// We'll just ignore parse failures for now
		parsedCert, err := x509.ParseCertificate(certBytes(cert))
		if err != nil || parsedCert.SerialNumber == nil || parsedCert.SerialNumber.Cmp(serial) != 0 {
			return true
		}
		// Duplicate the context so deleting it doesn't stop the enum
		dupCert := windows.CertDuplicateCertificateContext(cert)
		if dupCert == nil {
			deleteErr = fmt.Errorf("failed duplicating context")
			return false
		}
		if err := windows.CertDeleteCertificateFromStore(dupCert); err != nil {
			deleteErr = fmt.Errorf("failed deleting certificate: %v", err)
			return false
		}
		deletedAny = true
		return true
	})

	if deleteErr != nil {
		return deletedAny, deleteErr
	}
	return deletedAny, err
}
