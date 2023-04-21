package internal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
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

func (c Connection) getTransport() http.Transport {
	return c.transport
}

type RootYaml struct {
	Root YamlData `yaml:"root"`
}

type YamlData struct {
	LastModified int        `yaml:"lastModified"`
	Metadata     []Metadata `yaml:"metadata"`
}

type Metadata struct {
	Name string `yaml:"name"`
	Url  string `yaml:"url"`
}

func (m Metadata) getName() string {
	return m.Name
}

func (m Metadata) getUrl() string {
	return m.Url
}

func (y YamlData) GetNameListOwnURL() []string {
	var result []string
	for _, metadata := range y.Metadata {
		if len(metadata.getUrl()) > 0 {
			result = append(result, metadata.getName())
		}
	}
	return result
}

func (y YamlData) GetURLListOwnURL() []string {
	var result []string
	for _, metadata := range y.Metadata {
		if len(metadata.getUrl()) > 0 {
			result = append(result, metadata.getUrl())
		}
	}
	return result
}

func (y YamlData) FindURL(name string) string {
	for _, metadata := range y.Metadata {
		if metadata.getName() == name {
			return metadata.getUrl()
		}
	}
	return "No Data"
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

func SetTransport(domainName, ip string) http.Transport {

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
		} else if ip != "" {
			addr = fmt.Sprintf("%s:443", ip)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS13,
	}

	c := &Connection{
		transport: transport,
	}

	return c.getTransport()
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
	transport := SetTransport(domain, ip)
	// transport := c.transport

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
	if len(cert.DNSNames) > 0 {
		dnsToString := strings.Join(cert.DNSNames, " ")
		fmt.Printf("%s\t%s\n",
			color.HiBlackString("SAN DNS  "),
			color.HiMagentaString(strings.ReplaceAll(dnsToString, " ", "\n\t\t")))
	}
	PrintSplitFunc("Issuer Name", x509C.getIssuerName().String())
	PrintFunc("Common Name", x509C.getIssuerCommonName())
	PrintFunc("Start Date", x509C.getStartDate())

	colorDays := expireDateCountToColor(x509C.getExpireDate())
	PrintFunc("Expire Date", fmt.Sprintf("%s %s", color.HiGreenString(x509C.getExpireDate()), colorDays))
	PrintFunc("PubAlgorithm", x509C.getPubAlgorithm())
	PrintFunc("SigAlgorithm", x509C.getSigAlgorithm())
}

func getLeafCertification(peerCertificates []*x509.Certificate, ip string) {
	fmt.Printf("\n%s [%s]\n", color.HiWhiteString("Certificate"), color.HiYellowString(ip))

	for _, cert := range peerCertificates {
		if len(cert.DNSNames) > 0 {
			printCertifiacetInfo(cert)
		}
	}
}

func GetCertificateInfo(ip string, domain string) error {

	transport := SetTransport(domain, ip)
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), transport.TLSClientConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	getLeafCertification(conn.ConnectionState().PeerCertificates, ip)

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
			result, err := caRootCondition(cert.Subject.CommonName)
			if result && err != nil {
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

			result, err := caRootCondition(cert.Subject.CommonName)
			if result && err != nil {
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

func ParsingYaml(yamlObject *RootYaml) error {
	filename, _ := filepath.Abs("/opt/homebrew/lib/gossl/config.yaml")

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, &yamlObject)
	if err != nil {
		return err
	}

	return nil
}

func caRootCondition(cn string) (bool, error) {
	var r RootYaml
	err := ParsingYaml(&r)
	if err != nil {
		return false, err
	}

	for _, v := range r.Root.Metadata {
		if cn == v.getName() {
			return true, nil
		}
	}

	return false, nil
}

func DownloadCertificate(url string, out string) error {

	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	result, err := os.Create(dir + "/" + out)
	if err != nil {
		return err
	}
	defer result.Close()

	_, err = io.Copy(result, resp.Body)
	if err != nil {
		return err
	}

	return nil
}
