// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

// Three features adopted from upstream's open backlog, each asked for several
// times there and none of it merged since the project went dormant in 2024-08:
// name constraints (#657, #302, #309, #487), a validity flag (#513, #464,
// #339, #343) and a custom CA name (#229, #260, #240).

// --- -days ---------------------------------------------------------------

func TestCertExpirationDefaultsToUpstreamTwoYearsThreeMonths(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	got := certExpiration(now, 0)
	want := now.AddDate(2, 3, 0)
	if !got.Equal(want) {
		t.Errorf("default expiration = %v, want %v (unchanged upstream behaviour)", got, want)
	}
	// The upstream default exists to stay under Apple's 825-day ceiling for
	// locally-trusted roots. If that stops being true the default is wrong.
	if d := int(got.Sub(now).Hours() / 24); d >= 825 {
		t.Errorf("default validity is %d days, which is not under Apple's 825-day limit", d)
	}
}

func TestCertExpirationHonoursDays(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	for _, days := range []int{1, 30, 397, 824} {
		got := certExpiration(now, days)
		if want := now.AddDate(0, 0, days); !got.Equal(want) {
			t.Errorf("certExpiration(days=%d) = %v, want %v", days, got, want)
		}
	}
}

// Apple rejects a locally-trusted leaf over 825 days. mkcert cannot stop a
// caller asking for one, but it must not do it silently.
func TestExceedsAppleLimit(t *testing.T) {
	cases := map[int]bool{0: false, 1: false, 824: false, 825: true, 4000: true}
	for days, want := range cases {
		if got := exceedsAppleLimit(days); got != want {
			t.Errorf("exceedsAppleLimit(%d) = %v, want %v", days, got, want)
		}
	}
}

// --- -name-constraints ---------------------------------------------------

func TestParseNameConstraintsSplitsDNSFromCIDR(t *testing.T) {
	dns, ips, err := parseNameConstraints("example.test, 192.168.0.0/16 ,10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Upstream adds the leading-dot form so subdomains are permitted too.
	wantDNS := map[string]bool{"example.test": true, ".example.test": true}
	if len(dns) != len(wantDNS) {
		t.Errorf("got DNS constraints %v, want %d entries", dns, len(wantDNS))
	}
	for _, d := range dns {
		if !wantDNS[d] {
			t.Errorf("unexpected DNS constraint %q", d)
		}
	}
	if len(ips) != 2 {
		t.Fatalf("got %d IP ranges, want 2: %v", len(ips), ips)
	}
	if !ips[0].Contains(net.ParseIP("192.168.1.50")) {
		t.Errorf("192.168.0.0/16 does not contain 192.168.1.50")
	}
	if ips[1].Contains(net.ParseIP("192.168.1.50")) {
		t.Errorf("10.0.0.0/8 should not contain 192.168.1.50")
	}
}

func TestParseNameConstraintsRejectsGarbage(t *testing.T) {
	for _, spec := range []string{"192.168.0.0/33", "not a hostname!", "10.0.0.0/", ""} {
		if _, _, err := parseNameConstraints(spec); err == nil {
			t.Errorf("parseNameConstraints(%q) accepted an invalid constraint", spec)
		}
	}
}

// The reason this feature is worth having. A CA constrained to DNS ALONE --
// which is all upstream PR #657 implements -- does not restrict an IP SAN at
// all, because constraints apply per name type. Measured before writing this:
// such a CA happily signs 8.8.8.8. Our primary subject IS a LAN IP, so the IP
// half is the half that matters.
func TestConstrainedCARefusesNamesOutsideItsScope(t *testing.T) {
	m := &mkcert{nameConstraints: "example.test,192.168.0.0/16"}
	caCert, caKey := testCAFrom(t, m)

	cases := []struct {
		name    string
		ip      string
		dns     string
		allowed bool
	}{
		{"LAN IP inside the permitted range", "192.168.1.50", "", true},
		{"public IP outside it", "8.8.8.8", "", false},
		{"different private range not permitted", "10.1.2.3", "", false},
		{"permitted domain", "", "app.example.test", true},
		{"unrelated domain", "", "evil.attacker", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := signAndVerify(t, caCert, caKey, c.ip, c.dns); got != c.allowed {
				t.Errorf("verification allowed=%v, want %v", got, c.allowed)
			}
		})
	}
}

// The critical bit cannot be caught by a behavioural test: Go's verifier
// enforces name constraints whether or not the extension is marked critical, so
// every check above passes either way -- a mutation flipping it to false was
// MISSED until this test existed. It still matters. A verifier that does not
// understand nameConstraints MUST reject a certificate carrying it critical,
// and is free to ignore it otherwise, which is the difference between a
// constraint and a suggestion.
func TestNameConstraintsAreMarkedCritical(t *testing.T) {
	m := &mkcert{nameConstraints: "example.test,192.168.0.0/16"}
	caCert, _ := testCAFrom(t, m)

	const oidNameConstraints = "2.5.29.30"
	for _, ext := range caCert.Extensions {
		if ext.Id.String() == oidNameConstraints {
			if !ext.Critical {
				t.Error("the nameConstraints extension is not marked critical, so a verifier that does not understand it may ignore it")
			}
			return
		}
	}
	t.Error("no nameConstraints extension was emitted at all")
}

// Without constraints nothing changes -- the control. If this fails, the
// feature has altered the default CA and every existing CAROOT's behaviour.
func TestUnconstrainedCAIsUnchanged(t *testing.T) {
	m := &mkcert{}
	caCert, caKey := testCAFrom(t, m)
	if len(caCert.PermittedDNSDomains) != 0 || len(caCert.PermittedIPRanges) != 0 {
		t.Errorf("an unconstrained CA gained constraints: dns=%v ips=%v",
			caCert.PermittedDNSDomains, caCert.PermittedIPRanges)
	}
	if !signAndVerify(t, caCert, caKey, "8.8.8.8", "") {
		t.Error("an unconstrained CA refused a public IP; default behaviour changed")
	}
}

// --- -ca-name ------------------------------------------------------------

func TestCANameOverridesTheSubject(t *testing.T) {
	m := &mkcert{caName: "ws-scrcpy-web Local CA"}
	caCert, _ := testCAFrom(t, m)
	if caCert.Subject.CommonName != "ws-scrcpy-web Local CA" {
		t.Errorf("CommonName = %q, want the supplied name", caCert.Subject.CommonName)
	}
	if len(caCert.Subject.Organization) == 0 || caCert.Subject.Organization[0] != "ws-scrcpy-web Local CA" {
		t.Errorf("Organization = %v, want the supplied name", caCert.Subject.Organization)
	}
	// The user@host provenance is the point of the OU and must survive: it is
	// how you tell which machine minted a root you found in a trust store.
	if len(caCert.Subject.OrganizationalUnit) == 0 || caCert.Subject.OrganizationalUnit[0] == "" {
		t.Error("OrganizationalUnit lost the user@hostname provenance")
	}
}

func TestDefaultCANameIsUnchanged(t *testing.T) {
	m := &mkcert{}
	caCert, _ := testCAFrom(t, m)
	if len(caCert.Subject.Organization) == 0 || caCert.Subject.Organization[0] != "mkcert development CA" {
		t.Errorf("default Organization = %v, want \"mkcert development CA\"", caCert.Subject.Organization)
	}
}

// --- helpers -------------------------------------------------------------

// testCAFrom builds a CA from the template mkcert would use, without touching
// CAROOT or the filesystem.
func testCAFrom(t *testing.T, m *mkcert) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	tpl, err := m.newCATemplate([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("newCATemplate: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

// signAndVerify issues a leaf for the given name off the CA and reports
// whether it verifies against that CA as a root.
func signAndVerify(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ip, dnsName string) bool {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip != "" {
		tpl.IPAddresses = []net.IP{net.ParseIP(ip)}
	} else {
		tpl.DNSNames = []string{dnsName}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, leafKey.Public(), caKey)
	if err != nil {
		// A constraint violation can surface at signing time as well.
		return false
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	opts := x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if dnsName != "" {
		opts.DNSName = dnsName
	}
	_, err = leaf.Verify(opts)
	return err == nil
}
