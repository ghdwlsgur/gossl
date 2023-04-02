package internal

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/fatih/color"
)

func TestGetCertificate(t *testing.T) {

	ip := "185.199.110.153"
	domain := "ghdwlsgur.github.io"

	c := SetTransport(domain, ip)
	transport := c.transport

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), transport.TLSClientConfig)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	for _, cert := range conn.ConnectionState().PeerCertificates {
		fmt.Printf("\n[%s]\n", color.HiWhiteString(DistinguishCertificateWithConnection(cert)))
		printCertifiacetInfo(cert)
	}
}

func TestCARootCondition(t *testing.T) {

	cnList := []string{
		"Baltimore CyberTrust Root",
		"Cybertrust Global Root",
		"DigiCert Assured ID Root G2",
		"DigiCert Assured ID Root G3",
		"DigiCert Federated ID Root CA",
		"DigiCert Global Root G3",
		"DigiCert Private Services Root",
		"DigiCert Trusted Root G4",
		"GTE CyberTrust Global Root",
		"Verizon Global Root CA",
		"GeoTrust Primary Certification Authority",
		"GeoTrust Primary Certification Authority - G2",
		"GeoTrust Primary Certification Authority - G3",
		"DigiCert Assured ID Root CA",
		"DigiCert Global Root CA",
		"DigiCert High Assurance EV Root CA",
		"DigiCert Global Root G2",
		"DigiCert TLS RSA4096 Root G5",
		"DigiCert TLS ECC P384 Root G5",
		"DigiCert CS ECC P384 Root G5",
		"DigiCert CS RSA4096 Root G5",
		"DigiCert Client ECC P384 Root G5",
		"DigiCert Client RSA4096 Root G5", // 23
		"DigiCert SMIME ECC P384 Root G5",
		"DigiCert SMIME RSA4096 Root G5",
		"DigiCert ECC P384 Root G5",
		"DigiCert RSA4096 Root G5",
		"DigiCert EV RSA CA G2",
		"Symantec Class 3 Public Primary Certification Authority - G4",
		"Symantec Class 3 Public Primary Certification Authority - G6",
		"AAA Certificate Services",
		"Comodo Certification Authority",
		"COMODO ECC Certification Authority",
		"COMODO RSA Certification Authority",
		"Secure Certificate Services",
		"Trusted Certificate Services",
		"USERTrust RSA Certification Authority",
		"AddTrust Class 1 CA Root",
		"AddTrust External CA Root",
		"AddTrust Public CA Root",
		"AddTrust Qualified CA Root",
		"USERTrust ECC Certification Authority",
		"Thawte Primary Root CA",
		"Thawte Primary Root CA - G2",
		"Thawte Primary Root CA - G3",
		"Thawte Primary Root CA - G4",
		"GlobalSign Root R1",
		"GlobalSign Root R3",
		"GlobalSign Root R6",
		"GlobalSign Root R46",
		"GlobalSign ECC Root R5",
		"GlobalSign Root E46",
		"GlobalSign Client Authentication Root E45",
		"GlobalSign Client Authentication Root R45",
		"GlobalSign Code Signing Root E45",
		"GlobalSign Code Signing Root R45",
		"GlobalSign Document Signing Root E45",
		"GlobalSign Document Signing Root R45",
		"GlobalSign IoT Root E60",
		"GlobalSign IoT Root R60",
		"GlobalSign Secure Mail Root E45",
		"GlobalSign Secure Mail Root R45",
		"GlobalSign Timestamping Root R45",
		"GlobalSign Timestamping Root E46",
		"VeriSign Class 3 Public Primary Certification Authority - G3",
		"VeriSign Class 3 Public Primary Certification Authority - G4",
		"VeriSign Class 3 Public Primary Certification Authority - G5",
		"VeriSign Universal Root Certification Authority",
	}

	for _, cn := range cnList {
		result, err := caRootCondition(cn)
		if !result && err != nil {
			t.Error(result)
		}
	}
}
