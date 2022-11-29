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
}

type Connection struct {
	transport http.Transport
}

func (r x509Certificate) getSubject() pkix.Name {
	return r.Subject
}

func (r x509Certificate) getIssuerName() pkix.Name {
	return r.IssuerName
}

func (r x509Certificate) getIssuerCommonName() string {
	return r.IssuerCommonName
}

func (r x509Certificate) getStartDate() string {
	return r.StartDate
}

func (r x509Certificate) getExpireDate() string {
	return r.ExpireDate
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

func getCertificationField(peerCertificates []*x509.Certificate, ip string) {
	for _, cert := range peerCertificates {
		if len(cert.DNSNames) > 0 {
			formatDate := "2006-01-02"
			x509C := &x509Certificate{
				Subject:          cert.Subject,
				IssuerName:       cert.Issuer,
				IssuerCommonName: cert.Issuer.CommonName,
				StartDate:        cert.NotBefore.Format(formatDate),
				ExpireDate:       cert.NotAfter.Format(formatDate),
			}

			h := fmt.Sprintf("%s", cert.VerifyHostname(""))
			hl := strings.Split(h, ",")

			fmt.Printf("\n%s [%s]\n", color.HiWhiteString("Certificate"), color.HiYellowString(ip))
			PrintFunc("Verify Host", strings.TrimSpace(strings.Split(hl[:len(hl)-1][0], ":")[1]))
			PrintSplitFunc("Subject", x509C.getSubject().String())
			PrintSplitFunc("Issuer Name", x509C.getIssuerName().String())
			PrintFunc("Common Name", x509C.getIssuerCommonName())
			PrintFunc("Start Date", x509C.getStartDate())

			colorDays := expireDateCountToColor(x509C.getExpireDate())
			PrintFunc("Expire Date", fmt.Sprintf("%s %s", color.HiGreenString(x509C.getExpireDate()), colorDays))
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

func DistinguishCertificate(p *Pem, c *CertFile, pemBlockCount int) (string, error) {

	cert, err := x509.ParseCertificate(p.Block.Bytes)
	if err != nil {
		return "", err
	}

	if cert.IsCA {
		if cert.Subject.String() == cert.Issuer.String() {
			return "Root Certificate", nil
		} else {
			if cert.Subject.CommonName == "Sectigo RSA Domain Validation Secure Server CA" {
				return "Root Certificate", nil
			}
			if cert.Subject.CommonName == "GoGetSSL RSA DV CA" {
				return "Root Certificate", nil
			}
			return "Intermediate Certificate", nil
		}
	}

	if pemBlockCount > 2 {
		return "Unified Certificate", nil
	}

	return "Leaf Certificate", nil
}
