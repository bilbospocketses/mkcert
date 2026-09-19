// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// F6. The enumeration loop used to take the uintptr that LazyProc.Call returns
// and convert it straight back to a pointer -- "possible misuse of
// unsafe.Pointer", the one finding go vet reported on this repository. The fix
// is to call the typed crypt32 wrappers in golang.org/x/sys/windows, which
// return *CertContext and never round-trip through uintptr.
//
// These tests are the regression guard for that rewrite, because the risk of
// the change is not the vet finding, it is breaking code that manipulates the
// Windows root store. They are deliberately READ ONLY: forEachCert exists so
// enumeration can be exercised without going anywhere near the delete path.

func TestRootStoreEnumerationFindsCertificates(t *testing.T) {
	store, err := openWindowsRootStore()
	if err != nil {
		t.Fatalf("failed to open the Windows root store: %v", err)
	}
	defer store.close()

	n := 0
	seen := map[[32]byte]bool{}
	err = store.forEachCert(func(c *windows.CertContext) bool {
		if c.EncodedCert == nil {
			t.Error("certificate context has a nil EncodedCert")
		}
		if c.Length == 0 {
			t.Error("certificate context has zero Length")
		}
		seen[sha256.Sum256(certBytes(c))] = true
		n++
		return true
	})
	if err != nil {
		t.Fatalf("enumeration failed: %v", err)
	}

	// Counting is not enough. "n > 0" is satisfied by a loop that returns after
	// the first certificate or hands back the same context forever -- a mutation
	// run against an earlier version of this test proved exactly that, and it
	// passed. What matters is that the enumeration ADVANCES, so assert on the
	// number of DISTINCT certificates. A Windows root store ships dozens.
	if len(seen) < 2 {
		t.Errorf("enumeration yielded %d distinct certificate(s) over %d iteration(s); the loop is not advancing through the store", len(seen), n)
	}
	if len(seen) != n {
		t.Errorf("saw %d iterations but only %d distinct certificates; the same context is being returned more than once", n, len(seen))
	}
	t.Logf("enumerated %d root certificates, all distinct", n)
}

// Reading each context's DER is the part that used to cast the pointer to a
// (*[1 << 20]byte) and reslice it -- which silently truncates any certificate
// larger than a megabyte and is why unsafe.Slice exists. If the bytes handed
// back are not real DER, x509 will say so.
func TestRootStoreCertificatesParseAsX509(t *testing.T) {
	store, err := openWindowsRootStore()
	if err != nil {
		t.Fatalf("failed to open the Windows root store: %v", err)
	}
	defer store.close()

	var total, parsed int
	err = store.forEachCert(func(c *windows.CertContext) bool {
		total++
		if _, err := x509.ParseCertificate(certBytes(c)); err == nil {
			parsed++
		}
		return true
	})
	if err != nil {
		t.Fatalf("enumeration failed: %v", err)
	}
	if total == 0 {
		t.Fatal("enumerated zero certificates")
	}
	// Real trust stores carry the odd certificate Go's parser rejects, so this
	// asserts the bytes are overwhelmingly real DER rather than demanding
	// perfection from someone else's certificate store.
	if parsed*2 < total {
		t.Errorf("only %d of %d certificates parsed as X.509; the DER handed back looks wrong", parsed, total)
	}
	t.Logf("%d of %d root certificates parsed as X.509", parsed, total)
}

// The delete path is the dangerous half of this file, and the reason the
// rewrite was initially argued to be untestable: exercising it against the
// system ROOT store would mean removing a real root CA from the caller's
// machine. It does not have to be the ROOT store. CertOpenStore with
// CERT_STORE_PROV_MEMORY gives a throwaway store with the same API, so add,
// enumerate and delete can all be driven end to end against certificates this
// test made up, touching nothing outside the process.
func TestAddEnumerateDeleteRoundTripInAMemoryStore(t *testing.T) {
	handle, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_MEMORY,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0, 0, 0,
	)
	if err != nil {
		t.Fatalf("failed to open an in-memory certificate store: %v", err)
	}
	store := windowsRootStore(handle)
	defer store.close()

	keep, keepSerial := testCertificate(t)
	drop, dropSerial := testCertificate(t)
	if keepSerial.Cmp(dropSerial) == 0 {
		t.Fatal("the two test certificates share a serial number")
	}

	if err := store.addCert(keep); err != nil {
		t.Fatalf("addCert: %v", err)
	}
	if err := store.addCert(drop); err != nil {
		t.Fatalf("addCert: %v", err)
	}
	if got := countCerts(t, store); got != 2 {
		t.Fatalf("after adding 2 certificates the store holds %d", got)
	}

	deleted, err := store.deleteCertsWithSerial(dropSerial)
	if err != nil {
		t.Fatalf("deleteCertsWithSerial: %v", err)
	}
	if !deleted {
		t.Error("deleteCertsWithSerial reported deleting nothing, but the certificate was there")
	}
	if got := countCerts(t, store); got != 1 {
		t.Errorf("after deleting 1 of 2 certificates the store holds %d, want 1", got)
	}

	// The survivor must be the one we kept -- deleting by serial deleting the
	// WRONG certificate would still leave a count of 1.
	var survivorSerial string
	if err := store.forEachCert(func(c *windows.CertContext) bool {
		if parsed, err := x509.ParseCertificate(certBytes(c)); err == nil {
			survivorSerial = parsed.SerialNumber.String()
		}
		return true
	}); err != nil {
		t.Fatalf("enumeration failed: %v", err)
	}
	if survivorSerial != keepSerial.String() {
		t.Errorf("the wrong certificate survived: serial %s, want %s", survivorSerial, keepSerial)
	}

	// Deleting a serial that is no longer present must report false, not error.
	deleted, err = store.deleteCertsWithSerial(dropSerial)
	if err != nil {
		t.Fatalf("second deleteCertsWithSerial: %v", err)
	}
	if deleted {
		t.Error("deleteCertsWithSerial reported deleting a certificate that was already gone")
	}
}

func countCerts(t *testing.T, store windowsRootStore) int {
	t.Helper()
	n := 0
	if err := store.forEachCert(func(*windows.CertContext) bool { n++; return true }); err != nil {
		t.Fatalf("enumeration failed: %v", err)
	}
	return n
}

// testCertificate returns the DER of a throwaway self-signed certificate and
// its serial number.
func testCertificate(t *testing.T) ([]byte, *big.Int) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a test key: %v", err)
	}
	serial := randomSerialNumber()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mkcert test certificate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("failed to create a test certificate: %v", err)
	}
	return der, serial
}

// Stopping early must actually stop, or deleteCertsWithSerial cannot rely on
// the callback's return value and would walk the whole store regardless.
func TestForEachCertStopsWhenCallbackReturnsFalse(t *testing.T) {
	store, err := openWindowsRootStore()
	if err != nil {
		t.Fatalf("failed to open the Windows root store: %v", err)
	}
	defer store.close()

	n := 0
	if err := store.forEachCert(func(c *windows.CertContext) bool {
		n++
		return false
	}); err != nil {
		t.Fatalf("enumeration failed: %v", err)
	}
	if n != 1 {
		t.Errorf("callback ran %d times after returning false on the first; want 1", n)
	}
}
