// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"path/filepath"
	"strings"
	"testing"
)

// These tests cover the findings from the 2026-09-18 review of cert.go and
// main.go. Each one reproduces a specific defect; see todo_mkcert.md for the
// full write-up. Before this file the repository had no tests at all, so
// "go test ./..." passed by testing nothing.

// F3. A URL-shaped argument reaches fileNames unvalidated, because main.go's
// argument ladder accepts anything url.Parse reads as scheme+host. fileNames
// then substitutes only ":" and "*", so "/" and ".." survive into the output
// path. Measured 2026-09-18: run from esc/a/b, the argument below wrote its
// .pem and -key.pem into esc/a -- outside the working directory -- and still
// exited 0.
func TestFileNamesDoesNotEscapeTheWorkingDirectory(t *testing.T) {
	escapes := []string{
		"https://example.com/../../../pwned",
		"https://example.com/sub/thing",
		"http://a/b",
	}
	for _, host := range escapes {
		t.Run(host, func(t *testing.T) {
			m := &mkcert{}
			certFile, keyFile, p12File := m.fileNames([]string{host})
			for _, got := range []string{certFile, keyFile, p12File} {
				// Anything the caller did not choose must stay inside the
				// working directory: one path element, no separators, no "..".
				if strings.ContainsAny(strings.TrimPrefix(got, "./"), `/\`) {
					t.Errorf("output path escapes into a subdirectory: %q", got)
				}
				if strings.Contains(got, "..") {
					t.Errorf("output path contains a parent reference: %q", got)
				}
				if dir := filepath.Dir(got); dir != "." {
					t.Errorf("output path resolves outside cwd: %q (dir %q)", got, dir)
				}
			}
		})
	}
}

// The ordinary cases must keep working unchanged -- this is the control. If
// sanitising F3 also mangles a normal hostname or IP, the fix is worse than
// the bug, and a test that only proves the escape is closed would not notice.
func TestFileNamesKeepsOrdinaryNamesUnchanged(t *testing.T) {
	cases := []struct {
		hosts []string
		want  string
	}{
		{[]string{"example.org"}, "./example.org.pem"},
		{[]string{"192.168.1.50", "localhost"}, "./192.168.1.50+1.pem"},
		{[]string{"*.example.it"}, "./_wildcard.example.it.pem"},
		{[]string{"::1"}, "./__1.pem"},
	}
	for _, c := range cases {
		m := &mkcert{}
		certFile, _, _ := m.fileNames(c.hosts)
		if certFile != c.want {
			t.Errorf("fileNames(%v) = %q, want %q", c.hosts, certFile, c.want)
		}
	}
}

// F4b. makeCertFromCSR builds its hosts slice from the SANs of the certificate
// it just generated, then calls fileNames(hosts). A CSR that yields no SANs
// produces an empty slice, and fileNames indexes hosts[0] unconditionally --
// a panic rather than an error message.
func TestFileNamesDoesNotPanicOnNoHosts(t *testing.T) {
	m := &mkcert{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("fileNames panicked on an empty host list: %v", r)
		}
	}()
	certFile, _, _ := m.fileNames(nil)
	if certFile == "" {
		t.Error("fileNames returned an empty certificate path")
	}
}

// F4a. makeCertFromCSR sets ExtraExtensions: csr.Extensions, copying whatever
// the CSR asked for straight into a certificate signed by the local root.
// Verified against the Go stdlib: buildCertExtensions suppresses a generated
// extension whenever its OID appears in ExtraExtensions, and appends
// ExtraExtensions verbatim -- and makeCertFromCSR never sets
// BasicConstraintsValid, which is the sole gate on generating basicConstraints
// at all. So a CSR asking for CA:TRUE gets an intermediate CA off our root,
// unopposed by any generated extension.
func TestCSRExtensionsDropsBasicConstraints(t *testing.T) {
	caTrue, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{IsCA: true, MaxPathLen: -1})
	if err != nil {
		t.Fatalf("failed to build the basicConstraints payload: %v", err)
	}

	harmless := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}
	dangerous := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // basicConstraints
		Critical: true,
		Value:    caTrue,
	}

	got := safeCSRExtensions([]pkix.Extension{harmless, dangerous})

	for _, e := range got {
		if e.Id.Equal(dangerous.Id) {
			t.Error("basicConstraints survived: a CSR can mint an intermediate CA off our root")
		}
	}
	if len(got) != 1 || !got[0].Id.Equal(harmless.Id) {
		t.Errorf("expected the harmless extension to be preserved, got %d extension(s): %v", len(got), got)
	}
}

// A CSR that requests nothing dangerous must come through untouched, or the
// -csr flag stops honouring legitimate requested SANs and EKUs.
func TestCSRExtensionsPreservesEverythingElse(t *testing.T) {
	in := []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 17}},             // subjectAltName
		{Id: asn1.ObjectIdentifier{2, 5, 29, 15}},             // keyUsage
		{Id: asn1.ObjectIdentifier{2, 5, 29, 37}},             // extKeyUsage
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}}, // authorityInfoAccess
	}
	got := safeCSRExtensions(in)
	if len(got) != len(in) {
		t.Fatalf("dropped a safe extension: got %d, want %d", len(got), len(in))
	}
	for i := range in {
		if !got[i].Id.Equal(in[i].Id) {
			t.Errorf("extension %d changed: got %v, want %v", i, got[i].Id, in[i].Id)
		}
	}
}

// F5. With JAVA_HOME set and keytool present, EVERY invocation -- including a
// plain leaf generation that has nothing to do with Java -- runs
// "keytool -list", and the result goes through fatalIfCmdErr. A broken or
// partial JDK on the host therefore aborts certificate generation entirely.
// A *check* must be able to answer "no" without killing the process.
func TestCheckJavaReturnsFalseWhenKeytoolFails(t *testing.T) {
	origRun, origHasKeytool := runKeytool, hasKeytool
	defer func() { runKeytool, hasKeytool = origRun, origHasKeytool }()

	hasKeytool = true
	runKeytool = func(args ...string) ([]byte, error) {
		return []byte("keytool error: java.lang.Exception: Keystore file does not exist"),
			&exitError{"exit status 1"}
	}

	m := &mkcert{caCert: &x509.Certificate{Raw: []byte("not a real certificate")}}
	if m.checkJava() {
		t.Error("checkJava reported the CA as installed despite keytool failing")
	}
}

type exitError struct{ msg string }

func (e *exitError) Error() string { return e.msg }
