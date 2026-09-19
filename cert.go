// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var userAndHostname string

func init() {
	u, err := user.Current()
	if err == nil {
		userAndHostname = u.Username + "@"
	}
	if h, err := os.Hostname(); err == nil {
		userAndHostname += h
	}
	if err == nil && u.Name != "" && u.Name != u.Username {
		userAndHostname += " (" + u.Name + ")"
	}
}

func (m *mkcert) makeCert(hosts []string) {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}

	priv, err := m.generateKey(false)
	fatalIfErr(err, "failed to generate certificate key")
	pub := priv.(crypto.Signer).Public()

	expiration := certExpiration(time.Now(), m.days)

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"mkcert development certificate"},
			OrganizationalUnit: []string{userAndHostname},
		},

		NotBefore: time.Now(), NotAfter: expiration,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(tpl.IPAddresses) > 0 || len(tpl.DNSNames) > 0 || len(tpl.URIs) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if len(tpl.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	// IIS (the main target of PKCS #12 files), only shows the deprecated
	// Common Name in the UI. See issue #115.
	if m.pkcs12 {
		tpl.Subject.CommonName = hosts[0]
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, pub, m.caKey)
	fatalIfErr(err, "failed to generate certificate")

	certFile, keyFile, p12File := m.fileNames(hosts)

	if !m.pkcs12 {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		fatalIfErr(err, "failed to encode certificate key")
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

		if certFile == keyFile {
			err = os.WriteFile(keyFile, append(certPEM, privPEM...), 0600)
			fatalIfErr(err, "failed to save certificate and key")
		} else {
			err = os.WriteFile(certFile, certPEM, 0644)
			fatalIfErr(err, "failed to save certificate")
			err = os.WriteFile(keyFile, privPEM, 0600)
			fatalIfErr(err, "failed to save certificate key")
		}
	} else {
		domainCert, _ := x509.ParseCertificate(cert)
		// pkcs12.Encode was deprecated in go-pkcs12 v0.3.0 in favour of the
		// explicit encoders. LegacyRC2 is the one that keeps the previous
		// behaviour byte for byte -- same algorithms, same iteration counts,
		// and rand.Reader baked in -- so the bump does not silently change
		// what a ".p12" is encrypted with. Legacy (3DES) is more widely
		// readable and Modern (AES-256) is more secure; either is a
		// deliberate behaviour change, not a dependency bump.
		pfxData, err := pkcs12.LegacyRC2.Encode(priv, domainCert, []*x509.Certificate{m.caCert}, "changeit")
		fatalIfErr(err, "failed to generate PKCS#12")
		err = os.WriteFile(p12File, pfxData, 0644)
		fatalIfErr(err, "failed to save PKCS#12")
	}

	m.printHosts(hosts)

	if !m.pkcs12 {
		if certFile == keyFile {
			log.Printf("\nThe certificate and key are at \"%s\" ✅\n\n", certFile)
		} else {
			log.Printf("\nThe certificate is at \"%s\" and the key at \"%s\" ✅\n\n", certFile, keyFile)
		}
	} else {
		log.Printf("\nThe PKCS#12 bundle is at \"%s\" ✅\n", p12File)
		log.Printf("\nThe legacy PKCS#12 encryption password is the often hardcoded default \"changeit\" ℹ️\n\n")
	}

	log.Printf("It will expire on %s 🗓\n\n", expiration.Format("2 January 2006"))
}

func (m *mkcert) printHosts(hosts []string) {
	secondLvlWildcardRegexp := regexp.MustCompile(`(?i)^\*\.[0-9a-z_-]+$`)
	log.Printf("\nCreated a new certificate valid for the following names 📜")
	for _, h := range hosts {
		log.Printf(" - %q", h)
		if secondLvlWildcardRegexp.MatchString(h) {
			log.Printf("   Warning: many browsers don't support second-level wildcards like %q ⚠️", h)
		}
	}

	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") {
			log.Printf("\nReminder: X.509 wildcards only go one level deep, so this won't match a.b.%s ℹ️", h[2:])
			break
		}
	}
}

func (m *mkcert) generateKey(rootCA bool) (crypto.PrivateKey, error) {
	if m.ecdsa {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if rootCA {
		return rsa.GenerateKey(rand.Reader, 3072)
	}
	return rsa.GenerateKey(rand.Reader, 2048)
}

// sanitizeFileName reduces a certificate subject to a single safe path element.
// Without it a URL-shaped argument -- which main.go's ladder accepts whenever
// url.Parse finds a scheme and a host -- carries "/" and ".." straight into the
// output path, writing key material outside the working directory while still
// exiting 0.
func sanitizeFileName(name string) string {
	name = strings.NewReplacer("/", "_", "\\", "_").Replace(name)
	// Each pass strictly shortens the string, so this terminates.
	for strings.Contains(name, "..") {
		name = strings.Replace(name, "..", "_", -1)
	}
	return name
}

func (m *mkcert) fileNames(hosts []string) (certFile, keyFile, p12File string) {
	// makeCertFromCSR builds hosts from the generated certificate's SANs, which
	// can legitimately come back empty. Indexing hosts[0] there is a panic.
	subject := "certificate"
	if len(hosts) > 0 {
		subject = hosts[0]
	}
	defaultName := strings.Replace(subject, ":", "_", -1)
	defaultName = strings.Replace(defaultName, "*", "_wildcard", -1)
	defaultName = sanitizeFileName(defaultName)
	if len(hosts) > 1 {
		defaultName += "+" + strconv.Itoa(len(hosts)-1)
	}
	if m.client {
		defaultName += "-client"
	}

	certFile = "./" + defaultName + ".pem"
	if m.certFile != "" {
		certFile = m.certFile
	}
	keyFile = "./" + defaultName + "-key.pem"
	if m.keyFile != "" {
		keyFile = m.keyFile
	}
	p12File = "./" + defaultName + ".p12"
	if m.p12File != "" {
		p12File = m.p12File
	}

	return
}

// oidExtensionBasicConstraints is 2.5.29.19.
var oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

// safeCSRExtensions filters the extensions a CSR requested before they are
// copied into a certificate signed by the local root.
//
// makeCertFromCSR passes csr.Extensions straight into tpl.ExtraExtensions, and
// the stdlib appends ExtraExtensions verbatim while suppressing any generated
// extension that shares an OID with one of them. makeCertFromCSR also never
// sets BasicConstraintsValid, which is the only gate on generating
// basicConstraints at all -- so a CSR asking for CA:TRUE previously got an
// intermediate CA signed by the local root, with nothing competing against it.
// Dropping basicConstraints means the CA-ness of a certificate is decided here
// and not by whoever wrote the CSR.
func safeCSRExtensions(exts []pkix.Extension) []pkix.Extension {
	out := make([]pkix.Extension, 0, len(exts))
	for _, e := range exts {
		if e.Id.Equal(oidExtensionBasicConstraints) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")
	return serialNumber
}

func (m *mkcert) makeCertFromCSR() {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}

	csrPEMBytes, err := os.ReadFile(m.csrPath)
	fatalIfErr(err, "failed to read the CSR")
	csrPEM, _ := pem.Decode(csrPEMBytes)
	if csrPEM == nil {
		log.Fatalln("ERROR: failed to read the CSR: unexpected content")
	}
	if csrPEM.Type != "CERTIFICATE REQUEST" &&
		csrPEM.Type != "NEW CERTIFICATE REQUEST" {
		log.Fatalln("ERROR: failed to read the CSR: expected CERTIFICATE REQUEST, got " + csrPEM.Type)
	}
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	fatalIfErr(err, "failed to parse the CSR")
	fatalIfErr(csr.CheckSignature(), "invalid CSR signature")

	expiration := certExpiration(time.Now(), m.days)
	tpl := &x509.Certificate{
		SerialNumber:    randomSerialNumber(),
		Subject:         csr.Subject,
		ExtraExtensions: safeCSRExtensions(csr.Extensions), // requested SANs, KUs and EKUs, minus basicConstraints

		NotBefore: time.Now(), NotAfter: expiration,

		// If the CSR does not request a SAN extension, fix it up for them as
		// the Common Name field does not work in modern browsers. Otherwise,
		// this will get overridden.
		DNSNames: []string{csr.Subject.CommonName},

		// Likewise, if the CSR does not set KUs and EKUs, fix it up as Apple
		// platforms require serverAuth for TLS.
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(csr.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, csr.PublicKey, m.caKey)
	fatalIfErr(err, "failed to generate certificate")
	c, err := x509.ParseCertificate(cert)
	fatalIfErr(err, "failed to parse generated certificate")

	var hosts []string
	hosts = append(hosts, c.DNSNames...)
	hosts = append(hosts, c.EmailAddresses...)
	for _, ip := range c.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	for _, uri := range c.URIs {
		hosts = append(hosts, uri.String())
	}
	certFile, _, _ := m.fileNames(hosts)

	err = os.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save certificate")

	m.printHosts(hosts)

	log.Printf("\nThe certificate is at \"%s\" ✅\n\n", certFile)

	log.Printf("It will expire on %s 🗓\n\n", expiration.Format("2 January 2006"))
}

// loadCA will load or create the CA at CAROOT.
func (m *mkcert) loadCA() {
	if !pathExists(filepath.Join(m.CAROOT, rootName)) {
		m.newCA()
	}

	certPEMBlock, err := os.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read the CA certificate")
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	m.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")

	if !pathExists(filepath.Join(m.CAROOT, rootKeyName)) {
		return // keyless mode, where only -install works
	}

	keyPEMBlock, err := os.ReadFile(filepath.Join(m.CAROOT, rootKeyName))
	fatalIfErr(err, "failed to read the CA key")
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
	}
	m.caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA key")
}

func (m *mkcert) newCA() {
	priv, err := m.generateKey(true)
	fatalIfErr(err, "failed to generate the CA key")
	pub := priv.(crypto.Signer).Public()

	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	tpl, err := m.newCATemplate(skid[:])
	fatalIfErr(err, "failed to build the CA certificate template")

	// Constraining one name type leaves the other wide open, and a half-
	// constrained CA is more dangerous than an unconstrained one because it
	// looks protected. Say so rather than let it pass quietly.
	if m.nameConstraints != "" {
		switch {
		case len(tpl.PermittedIPRanges) == 0:
			log.Printf("Warning: these name constraints cover DNS names only, so this CA can still sign ANY IP address")
		case len(tpl.PermittedDNSDomains) == 0:
			log.Printf("Warning: these name constraints cover IP addresses only, so this CA can still sign ANY DNS name")
		}
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")
	err = os.WriteFile(filepath.Join(m.CAROOT, rootKeyName), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to save CA key")

	err = os.WriteFile(filepath.Join(m.CAROOT, rootName), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save CA certificate")

	log.Printf("Created a new local CA 💥\n")
}

// newCATemplate builds the CA certificate template. Split out of newCA so the
// subject and the name constraints can be exercised without writing a CAROOT.
func (m *mkcert) newCATemplate(skid []byte) (*x509.Certificate, error) {
	// Upstream #229/#260/#240: a root labelled "mkcert <user>@<host>" tells the
	// person being asked to trust it nothing about which application wanted it.
	organization, commonName := "mkcert development CA", "mkcert "+userAndHostname
	if m.caName != "" {
		organization, commonName = m.caName, m.caName
	}

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization: []string{organization},
			// Deliberately kept even when -ca-name is set: this is how you tell
			// which user on which machine minted a root found in a trust store.
			OrganizationalUnit: []string{userAndHostname},

			// The CommonName is required by iOS to show the certificate in the
			// "Certificate Trust Settings" menu.
			// https://github.com/FiloSottile/mkcert/issues/47
			CommonName: commonName,
		},
		SubjectKeyId: skid,

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	if m.nameConstraints != "" {
		dns, ips, err := parseNameConstraints(m.nameConstraints)
		if err != nil {
			return nil, err
		}
		// Despite the field name this marks the whole nameConstraints
		// extension critical, so a verifier that cannot understand it must
		// reject rather than ignore it.
		tpl.PermittedDNSDomainsCritical = true
		tpl.PermittedDNSDomains = dns
		tpl.PermittedIPRanges = ips
	}

	return tpl, nil
}

// certExpiration returns a leaf certificate's notAfter. days <= 0 keeps
// upstream's 2 years and 3 months.
func certExpiration(now time.Time, days int) time.Time {
	if days > 0 {
		return now.AddDate(0, 0, days)
	}
	// Certificates last for 2 years and 3 months, which is always less than
	// 825 days, the limit that macOS/iOS apply to all certificates,
	// including custom roots. See https://support.apple.com/en-us/HT210176.
	return now.AddDate(2, 3, 0)
}

// appleValidityLimitDays is the ceiling macOS and iOS apply to any certificate,
// locally-trusted roots included.
const appleValidityLimitDays = 825

func exceedsAppleLimit(days int) bool {
	return days >= appleValidityLimitDays
}

// constraintHostRegexp matches a DNS name usable as a constraint. Same shape as
// the hostname check in main.go, minus the wildcard: a constraint is a suffix,
// so "*.example.test" would be a category error rather than a broader rule.
var constraintHostRegexp = regexp.MustCompile(`(?i)^[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)

// parseNameConstraints splits a comma-separated constraint list into DNS
// suffixes and IP ranges. An entry containing "/" is read as CIDR, everything
// else as a DNS suffix.
//
// BOTH halves matter, and that is the whole point of the feature. X.509 applies
// name constraints PER NAME TYPE: constraining dNSName alone leaves iPAddress
// entirely unconstrained. Measured against upstream PR #657, which sets only
// PermittedDNSDomains -- a CA so constrained still happily signs 8.8.8.8. Since
// the subject here is usually a LAN IP, DNS-only constraints would be security
// theatre.
func parseNameConstraints(spec string) (dns []string, ips []*net.IPNet, err error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil, fmt.Errorf("no name constraints given")
	}
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		switch {
		case entry == "":
			return nil, nil, fmt.Errorf("empty entry in name constraint list %q", spec)
		case strings.Contains(entry, "/"):
			_, ipNet, cidrErr := net.ParseCIDR(entry)
			if cidrErr != nil {
				return nil, nil, fmt.Errorf("invalid CIDR name constraint %q: %v", entry, cidrErr)
			}
			ips = append(ips, ipNet)
		case constraintHostRegexp.MatchString(entry):
			// The bare name permits the name itself; the leading dot permits
			// everything beneath it.
			dns = append(dns, entry, "."+entry)
		default:
			return nil, nil, fmt.Errorf("invalid DNS name constraint %q", entry)
		}
	}
	return dns, ips, nil
}

func (m *mkcert) caUniqueName() string {
	return "mkcert development CA " + m.caCert.SerialNumber.String()
}
