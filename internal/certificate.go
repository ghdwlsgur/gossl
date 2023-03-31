package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
)

type x509Certificate struct {
	Subject          pkix.Name
	IssuerName       pkix.Name
	IssuerCommonName string
	StartDate        string
	ExpireDate       string
	PubAlgorithm     string
	SigAlgorithm     string
}

type Connection struct {
	transport http.Transport
}

func (c x509Certificate) getSubject() pkix.Name {
	return c.Subject
}

func (c x509Certificate) getIssuerName() pkix.Name {
	return c.IssuerName
}

func (c x509Certificate) getIssuerCommonName() string {
	return c.IssuerCommonName
}

func (c x509Certificate) getStartDate() string {
	return c.StartDate
}

func (c x509Certificate) getExpireDate() string {
	return c.ExpireDate
}

func (c x509Certificate) getPubAlgorithm() string {
	return c.PubAlgorithm
}

func (c x509Certificate) getSigAlgorithm() string {
	return c.SigAlgorithm
}

func SetTransport(domainName, ip string) *Connection {

	transport := http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == fmt.Sprintf("%s:443", domainName) {
			addr = fmt.Sprintf("%s:443", ip)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS13,
	}

	return &Connection{
		transport: transport,
	}
}

func expireDateCountToColor(expireDate string) string {
	nowFormat, _ := time.Parse("2006-01-02", time.Now().Format("2006-01-02"))
	expireFormat, _ := time.Parse("2006-01-02", expireDate)

	days := int32(expireFormat.Sub(nowFormat).Hours() / 24)
	if days < 30 {
		return color.HiRedString(fmt.Sprintf("[%v days]", days))
	}
	return color.HiGreenString(fmt.Sprintf("[%v days]", days))
}

func GetCertificate(domain, ip string) error {
	c := SetTransport(domain, ip)
	transport := c.transport

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), transport.TLSClientConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	for _, cert := range conn.ConnectionState().PeerCertificates {
		fmt.Printf("\n[ %s ]\n", color.HiWhiteString(DistinguishCertificateWithConnection(cert)))
		printCertifiacetInfo(cert)
	}

	return nil
}

func printCertifiacetInfo(cert *x509.Certificate) {
	formatDate := "2006-01-02"
	x509C := &x509Certificate{
		Subject:          cert.Subject,
		IssuerName:       cert.Issuer,
		IssuerCommonName: cert.Issuer.CommonName,
		StartDate:        cert.NotBefore.Format(formatDate),
		ExpireDate:       cert.NotAfter.Format(formatDate),
		PubAlgorithm:     cert.PublicKeyAlgorithm.String(),
		SigAlgorithm:     cert.SignatureAlgorithm.String(),
	}
	h := fmt.Sprintf("%s", cert.VerifyHostname(""))
	hl := strings.Split(h, ",")

	PrintFunc("Verify Host", strings.TrimSpace(strings.Split(hl[:len(hl)-1][0], ":")[1]))
	PrintSplitFunc("Subject", x509C.getSubject().String())
	PrintSplitFunc("Issuer Name", x509C.getIssuerName().String())
	PrintFunc("Common Name", x509C.getIssuerCommonName())
	PrintFunc("Start Date", x509C.getStartDate())

	colorDays := expireDateCountToColor(x509C.getExpireDate())
	PrintFunc("Expire Date", fmt.Sprintf("%s %s", color.HiGreenString(x509C.getExpireDate()), colorDays))
	PrintFunc("PubAlgorithm", x509C.getPubAlgorithm())
	PrintFunc("SigAlgorithm", x509C.getSigAlgorithm())
}

func getCertificationField(peerCertificates []*x509.Certificate, ip string) {
	fmt.Printf("\n%s [%s]\n", color.HiWhiteString("Certificate"), color.HiYellowString(ip))

	for _, cert := range peerCertificates {
		if len(cert.DNSNames) > 0 {
			printCertifiacetInfo(cert)
		}
	}
}

func GetCertificateInfo(ip string, domain string) error {

	c := SetTransport(domain, ip)
	transport := c.transport

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), transport.TLSClientConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	getCertificationField(conn.ConnectionState().PeerCertificates, ip)

	return nil
}

func CountPemBlock(bytes []byte) int {
	var pemBlockCount int

	for {
		var block *pem.Block
		block, bytes = pem.Decode(bytes)

		pemBlockCount++

		if block == nil {
			return pemBlockCount
		}
		if len(bytes) == 0 {
			return pemBlockCount
		}
	}
}

func DistinguishCertificateWithConnection(cert *x509.Certificate) string {
	if len(cert.DNSNames) > 0 {
		return "Leaf Certificate"
	}

	if cert.IsCA {
		if cert.Subject.String() == cert.Issuer.String() {
			return "Root Certificate"
		} else {
			if caRootCondition(cert.Subject.CommonName) {
				return "Root Certificate"
			}
			return "Intermediate Certificate"
		}
	}

	return ""
}

func DistinguishCertificate(p *Pem, _ *CertFile, pemBlockCount int) (string, error) {

	cert, err := x509.ParseCertificate(p.Block.Bytes)
	if err != nil {
		return "", err
	}

	if cert.IsCA && pemBlockCount == 1 {
		rootFormat := fmt.Sprintf("%s [in %d block]", "Root Certificate", pemBlockCount)
		if cert.Subject.String() == cert.Issuer.String() {
			return rootFormat, nil
		} else {

			if caRootCondition(cert.Subject.CommonName) {
				return rootFormat, nil
			}

			// Intermediate Certificate
			intermediateFormat := fmt.Sprintf("%s [in %d block]", "Intermediate Certificate", pemBlockCount)
			return intermediateFormat, nil

		}
	}

	unifiedFormat := fmt.Sprintf("%s [in %d block]", "Unified Certificate", pemBlockCount)
	if pemBlockCount >= 2 {
		return unifiedFormat, nil
	}

	leafFormat := fmt.Sprintf("%s [in %d block]", "Leaf Certificate", pemBlockCount)
	// Leaf Certificate
	return leafFormat, nil
}

// https://www.digicert.com/kb/digicert-root-certificates.htm
func caRootCondition(cn string) bool {
	var result = false

	// DigiCert
	// https://knowledge.digicert.com/generalinformation/digicert-root-and-intermediate-ca-certificate-updates-2023.html
	switch cn {
	case "Baltimore CyberTrust Root": // distrust date: April 15, 2025
		result = true
	case "Cybertrust Global Root":
		result = true
	case "DigiCert Assured ID Root G2":
		result = true
	case "DigiCert Assured ID Root G3":
		result = true
	case "DigiCert Federated ID Root CA":
		result = true
	case "DigiCert Global Root G3":
		result = true
	case "DigiCert Private Services Root":
		result = true
	case "DigiCert Trusted Root G4":
		result = true
	case "GTE CyberTrust Global Root":
		result = true
	case "Verizon Global Root CA":
		result = true
	case "GeoTrust Primary Certification Authority":
		result = true
	case "GeoTrust Primary Certification Authority - G2":
		result = true
	case "GeoTrust Primary Certification Authority - G3":
		result = true
	case "DigiCert Assured ID Root CA": // distrust date: April 15, 2026
		result = true
	case "DigiCert Global Root CA": // distrust date: April 15, 2026
		result = true
	case "DigiCert High Assurance EV Root CA": // distrust date: April 15, 2026
		result = true
	case "DigiCert Global Root G2": // distrust date: April 15, 2029
		result = true
	case "DigiCert TLS RSA4096 Root G5": // distrust date: Jan 15, 2036
		result = true
	case "DigiCert TLS ECC P384 Root G5":
		result = true
	case "DigiCert CS ECC P384 Root G5":
		result = true
	case "DigiCert CS RSA4096 Root G5":
		result = true
	case "DigiCert Client ECC P384 Root G5":
		result = true
	case "DigiCert Client RSA4096 Root G5":
		result = true
	case "DigiCert SMIME ECC P384 Root G5":
		result = true
	case "DigiCert SMIME RSA4096 Root G5":
		result = true
	case "DigiCert ECC P384 Root G5":
		result = true
	case "DigiCert RSA4096 Root G5":
		result = true
	case "DigiCert EV RSA CA G2":
		result = true
	case "Symantec Class 3 Public Primary Certification Authority - G4":
		result = true
	case "Symantec Class 3 Public Primary Certification Authority - G6":
		result = true
	}

	// Sectigo
	// https://sectigo.com/resource-library/sectigo-root-intermediate-certificate-files
	// https://secure.sectigo.com/products/publiclyDisclosedSubCACerts
	switch cn {
	case "AAA Certificate Services":
		result = true
	case "Comodo Certification Authority":
		result = true
	case "COMODO ECC Certification Authority":
		result = true
	case "COMODO RSA Certification Authority":
		result = true
	case "Secure Certificate Services":
		result = true
	case "Trusted Certificate Services":
		result = true
	case "USERTrust RSA Certification Authority":
		result = true
	case "AddTrust Class 1 CA Root":
		result = true
	case "AddTrust External CA Root":
		result = true
	case "AddTrust Public CA Root":
		result = true
	case "AddTrust Qualified CA Root":
		result = true
	case "USERTrust ECC Certification Authority":
		result = true
	}

	// Thawte
	// https://www.thawte.com/roots/
	switch cn {
	case "Thawte Primary Root CA": // distrust date: Jul 16, 2036
		result = true
	case "Thawte Primary Root CA - G2": // distrust date: Jan 18, 2038
		result = true
	case "Thawte Primary Root CA - G3": // distrust date: Dec 1, 2037
		result = true
	case "Thawte Primary Root CA - G4": // distrust date: Dec 1, 2037
		result = true
	}

	// GlobalSign
	// https://support.globalsign.com/ca-certificates/root-certificates/globalsign-root-certificates
	switch cn {
	case "GlobalSign Root R1":
		result = true
	case "GlobalSign Root R3":
		result = true
	case "GlobalSign Root R6":
		result = true
	case "GlobalSign Root R46":
		result = true
	case "GlobalSign ECC Root R5":
		result = true
	case "GlobalSign Root E46":
		result = true
	case "GlobalSign Client Authentication Root E45":
		result = true
	case "GlobalSign Client Authentication Root R45":
		result = true
	case "GlobalSign Code Signing Root E45":
		result = true
	case "GlobalSign Code Signing Root R45":
		result = true
	case "GlobalSign Document Signing Root E45":
		result = true
	case "GlobalSign Document Signing Root R45":
		result = true
	case "GlobalSign IoT Root E60":
		result = true
	case "GlobalSign IoT Root R60":
		result = true
	case "GlobalSign Secure Mail Root E45":
		result = true
	case "GlobalSign Secure Mail Root R45":
		result = true
	case "GlobalSign Timestamping Root R45":
		result = true
	case "GlobalSign Timestamping Root E46":
		result = true
	}

	// VeriSign
	switch cn {
	case "VeriSign Class 3 Public Primary Certification Authority - G3":
		result = true
	case "VeriSign Class 3 Public Primary Certification Authority - G4":
		result = true
	case "VeriSign Class 3 Public Primary Certification Authority - G5":
		result = true
	case "VeriSign Universal Root Certification Authority":
		result = true
	}

	return result
}
