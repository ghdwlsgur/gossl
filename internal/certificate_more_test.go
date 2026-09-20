package internal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout 은 f 가 표준출력에 쓴 내용을 돌려준다.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	f()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestX509CertificateAccessors(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := x509.ParseCertificate(newCert(t, false, []string{"acc.test"}, "acc.test", &k.PublicKey, k))
	if err != nil {
		t.Fatal(err)
	}

	c := x509Certificate{
		Subject:          cert.Subject,
		IssuerName:       cert.Issuer,
		IssuerCommonName: cert.Issuer.CommonName,
		StartDate:        cert.NotBefore.Format("2006-01-02"),
		ExpireDate:       cert.NotAfter.Format("2006-01-02"),
		PubAlgorithm:     cert.PublicKeyAlgorithm.String(),
		SigAlgorithm:     cert.SignatureAlgorithm.String(),
	}

	if c.getSubject().CommonName != "acc.test" {
		t.Error("getSubject")
	}
	if c.getIssuerName().CommonName != "acc.test" {
		t.Error("getIssuerName")
	}
	if c.getIssuerCommonName() != "acc.test" {
		t.Error("getIssuerCommonName")
	}
	if c.getStartDate() == "" || c.getExpireDate() == "" {
		t.Error("날짜 접근자가 비어 있다")
	}
	if c.getPubAlgorithm() != "ECDSA" {
		t.Errorf("getPubAlgorithm = %q", c.getPubAlgorithm())
	}
	if !strings.Contains(c.getSigAlgorithm(), "ECDSA") {
		t.Errorf("getSigAlgorithm = %q", c.getSigAlgorithm())
	}
}

func TestExpireDateCountToColor(t *testing.T) {
	soon := time.Now().AddDate(0, 0, 3).Format("2006-01-02")
	far := time.Now().AddDate(0, 0, 200).Format("2006-01-02")

	if got := expireDateCountToColor(soon); !strings.Contains(got, "days") {
		t.Errorf("임박한 만료 = %q", got)
	}
	if got := expireDateCountToColor(far); !strings.Contains(got, "200 days") {
		t.Errorf("여유 있는 만료 = %q, 200 days 를 포함해야 한다", got)
	}
	// 파싱 불가한 입력도 패닉하지 않아야 한다.
	_ = expireDateCountToColor("not-a-date")
}

func TestHostNames_Variants(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	leaf, _ := x509.ParseCertificate(newCert(t, false, []string{"a.com", "b.com"}, "a", &k.PublicKey, k))
	if got := HostNames(leaf); got != "a.com, b.com" {
		t.Errorf("DNS 이름 = %q", got)
	}

	ca, _ := x509.ParseCertificate(newCert(t, true, nil, "Root", &k.PublicKey, k))
	if got := HostNames(ca); got != "certificate is not valid for any names" {
		t.Errorf("이름 없는 인증서 = %q", got)
	}
}

func TestGetSubjectCNandIssuerCN(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := newCert(t, false, []string{"cn.test"}, "cn.test", &k.PublicKey, k)

	got, err := GetSubjectCNandIssuerCN(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "cn.test" || got[1] != "cn.test" {
		t.Errorf("GetSubjectCNandIssuerCN = %v", got)
	}

	if _, err := GetSubjectCNandIssuerCN(&pem.Block{Bytes: nil}); err == nil {
		t.Error("빈 블록인데 오류를 반환하지 않았다")
	}
	if _, err := GetSubjectCNandIssuerCN(&pem.Block{Bytes: []byte("garbage")}); err == nil {
		t.Error("파싱 불가한 블록인데 오류를 반환하지 않았다")
	}
}

func TestPrintFuncs(t *testing.T) {
	out := captureStdout(t, func() { PrintFunc("Short", "value") })
	if !strings.Contains(out, "value") {
		t.Errorf("PrintFunc 출력 = %q", out)
	}

	out = captureStdout(t, func() { PrintFunc("LongFieldName", "value") })
	if !strings.Contains(out, "value") {
		t.Errorf("긴 필드명 출력 = %q", out)
	}

	out = captureStdout(t, func() { PrintSplitFunc("Subject", "CN=a,O=b,C=KR") })
	for _, want := range []string{"CN=a", "O=b", "C=KR"} {
		if !strings.Contains(out, want) {
			t.Errorf("PrintSplitFunc 출력에 %q 가 없다: %q", want, out)
		}
	}
}

func TestSetTransportPinsIP(t *testing.T) {
	tr := SetTransport("example.com", "192.0.2.1")
	if tr.TLSClientConfig.ServerName != "example.com" {
		t.Errorf("SNI 가 도메인이어야 한다: %q", tr.TLSClientConfig.ServerName)
	}
	if tr.DialContext == nil {
		t.Fatal("DialContext 가 설정되지 않았다")
	}

	// ip 가 없으면 원래 주소를 그대로 쓴다.
	trNoIP := SetTransport("example.com", "")
	if trNoIP.TLSClientConfig.ServerName != "example.com" {
		t.Error("ip 가 없어도 SNI 는 도메인이어야 한다")
	}
}

func TestDialTLS_Errors(t *testing.T) {
	// 닫힌 포트로 즉시 실패시킨다.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close()

	if _, err := DialTLS("localhost", addr.IP.String()); err == nil {
		t.Error("접속 실패인데 오류를 반환하지 않았다")
	}
	if _, err := DialTLS("this-domain-does-not-exist.invalid", ""); err == nil {
		t.Error("해석 불가 도메인인데 오류를 반환하지 않았다")
	}
}

func TestGetRecordIPv4AndHost(t *testing.T) {
	if err := GetHost("this-domain-does-not-exist.invalid"); err == nil {
		t.Error("없는 도메인인데 오류를 반환하지 않았다")
	}
	if _, err := GetRecordIPv4("this-domain-does-not-exist.invalid"); err == nil {
		t.Error("없는 도메인인데 오류를 반환하지 않았다")
	}

	ips, err := GetRecordIPv4("localhost")
	if err != nil {
		t.Skipf("localhost 해석 실패: %v", err)
	}
	for _, ip := range ips {
		if net.ParseIP(ip).To4() == nil {
			t.Errorf("IPv4 가 아닌 주소가 포함됐다: %s", ip)
		}
	}
}

func TestWrapperGenerics(t *testing.T) {
	a := newField(Answer{Name: "one"})
	if getAnswer(a).Name != "one" {
		t.Errorf("Answer 래퍼 = %+v", getAnswer(a))
	}

	l := newField(AnswerList{Name: []string{"a", "b"}})
	if got := getAnswer(l).Name; len(got) != 2 || got[0] != "a" {
		t.Errorf("AnswerList 래퍼 = %v", got)
	}
}

// SetTransport 의 DialContext 클로저를 직접 호출해 주소 치환을 확인한다.
func TestSetTransport_DialContextRewritesAddr(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, port, _ := net.SplitHostPort(l.Addr().String())

	// ip 를 주면 요청 주소와 무관하게 그 ip 로 붙는다.
	tr := SetTransport("example.com", host)
	conn, err := tr.DialContext(context.Background(), "tcp", net.JoinHostPort("example.com", port))
	if err != nil {
		t.Fatalf("지정한 ip 로 접속하지 못했다: %v", err)
	}
	conn.Close()

	// 포트를 파싱할 수 없는 주소를 주면 443 으로 떨어진다.
	if _, err := tr.DialContext(context.Background(), "tcp", "malformed-address"); err == nil {
		t.Log("443 으로 폴백해 접속을 시도했다")
	}

	// ip 가 비면 주소를 그대로 쓴다.
	trNoIP := SetTransport("localhost", "")
	conn2, err := trNoIP.DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("원래 주소로 접속하지 못했다: %v", err)
	}
	conn2.Close()
}

// 아래 셋은 실제 TLS 서버가 필요하다. DialTLS 가 443 을 고정하므로
// 임시 서버를 띄울 수 없어 공개 도메인을 쓴다.
func TestCertificateInfoOverNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("네트워크가 필요해 건너뜀")
	}
	const domain = "example.com"

	ips, err := GetRecordIPv4(domain)
	if err != nil || len(ips) == 0 {
		t.Skipf("%s 의 IPv4 를 얻지 못했다: %v", domain, err)
	}

	out := captureStdout(t, func() {
		if err := GetCertificate(domain, ips[0]); err != nil {
			t.Errorf("GetCertificate: %v", err)
		}
	})
	for _, want := range []string{"Verify Host", "Subject", "Expire Date", "PubAlgorithm"} {
		if !strings.Contains(out, want) {
			t.Errorf("GetCertificate 출력에 %q 가 없다", want)
		}
	}

	out = captureStdout(t, func() {
		if err := GetCertificateInfo(ips[0], domain); err != nil {
			t.Errorf("GetCertificateInfo: %v", err)
		}
	})
	if !strings.Contains(out, "Certificate") {
		t.Errorf("GetCertificateInfo 출력 = %q", out)
	}

	// 접속 실패 경로
	if err := GetCertificate("this-domain-does-not-exist.invalid", ""); err == nil {
		t.Error("없는 도메인인데 오류를 반환하지 않았다")
	}
	if err := GetCertificateInfo("", "this-domain-does-not-exist.invalid"); err == nil {
		t.Error("없는 도메인인데 오류를 반환하지 않았다")
	}
}
