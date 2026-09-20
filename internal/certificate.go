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
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"gopkg.in/yaml.v3"
)

const (
	rootCertificateDownloadUrl = "https://ghdwlsgur.github.io/files/root_cert_config.yaml"
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
	transport *http.Transport
}

func (c Connection) getTransport() *http.Transport {
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

// dialTimeout 은 접속과 핸드셰이크에 공통으로 쓰는 제한 시간이다.
const dialTimeout = 10 * time.Second

func SetTransport(domainName, ip string) *http.Transport {

	transport := &http.Transport{
		TLSHandshakeTimeout: dialTimeout,
	}

	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if ip != "" {
			// 도메인이 아니라 지정된 IP 로 붙는다. 포트는 원래 요청의 것을 유지한다.
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "443"
			}
			addr = net.JoinHostPort(ip, port)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	transport.TLSClientConfig = tlsConfig(domainName)

	c := &Connection{
		transport: transport,
	}

	return c.getTransport()
}

// tlsConfig 는 인증서를 "검사"하기 위한 설정이다.
// 만료되었거나 체인이 끊긴 인증서도 봐야 하므로 검증은 끄되,
// ServerName 은 반드시 도메인으로 둔다. 그래야 SNI 로 올바른 인증서를 받는다.
func tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // 검사 도구이므로 의도적으로 검증하지 않는다
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
}

// DialTLS 는 ip 가 주어지면 그 주소로 접속하고, SNI 는 domain 으로 보낸다.
func DialTLS(domain, ip string) (*tls.Conn, error) {
	host := domain
	if ip != "" {
		host = ip
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), tlsConfig(domain))
	if err != nil {
		if ip != "" {
			return nil, fmt.Errorf("failed to connect to %s (%s): %w", domain, ip, err)
		}
		return nil, fmt.Errorf("failed to connect to %s: %w", domain, err)
	}
	return conn, nil
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
	conn, err := DialTLS(domain, ip)
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

// HostNames 는 인증서가 보증하는 이름을 사람이 읽을 형태로 돌려준다.
// 예전 구현은 VerifyHostname("") 의 오류 문자열을 쉼표와 콜론으로 잘라 썼는데,
// 오류 메시지 형식이 다르면 인덱스 범위를 벗어났다.
func HostNames(cert *x509.Certificate) string {
	names := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return "certificate is not valid for any names"
	}
	return strings.Join(names, ", ")
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
	PrintFunc("Verify Host", HostNames(cert))
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

	conn, err := DialTLS(domain, ip)
	if err != nil {
		return err
	}
	defer conn.Close()

	getLeafCertification(conn.ConnectionState().PeerCertificates, ip)

	return nil
}

// CountPemBlock 은 입력에 들어 있는 PEM 블록의 개수를 센다.
// 후행 개행이나 공백은 블록으로 세지 않는다.
func CountPemBlock(data []byte) int {
	count := 0

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return count
		}
		count++
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
			// 원격 목록 조회가 실패하면 루트로 단정하지 않고 중간 인증서로 둔다.
			result, err := caRootCondition(cert.Subject.CommonName)
			if err == nil && result {
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
			if err == nil && result {
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

	client := resty.New()

	resp, err := client.R().
		SetHeader("Referer", "https://ghdwlsgur.github.io/").
		SetHeader("Content-Type", "application/yaml").
		Get(rootCertificateDownloadUrl)
	if err != nil {
		return fmt.Errorf("failed to download root certificate list: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("failed to download root certificate list: status %d", resp.StatusCode())
	}

	if err := yaml.Unmarshal(resp.Body(), yamlObject); err != nil {
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

func GetSubjectCNandIssuerCN(pem *pem.Block) ([]string, error) {
	if len(pem.Bytes) <= 0 {
		return nil, fmt.Errorf("file content is empty")
	}

	cert, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		return nil, err
	}

	return []string{cert.Subject.CommonName, cert.Issuer.CommonName}, nil
}
