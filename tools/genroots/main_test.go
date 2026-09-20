package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeRoot 는 자기 서명 루트 인증서를 만들어 PEM 과 지문을 돌려준다.
func makeRoot(t *testing.T, cn string, notAfter time.Time) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		strings.ToUpper(hex.EncodeToString(sum[:]))
}

func record(name, trust, distrust, pemText, fingerprint string) map[string]string {
	return map[string]string{
		"Owner":                           "Test Owner",
		"Common Name or Certificate Name": name,
		"SHA-256 Fingerprint":             fingerprint,
		"Trust Bits":                      trust,
		"Distrust for TLS After Date":     distrust,
		"PEM Info":                        "'" + pemText + "'",
	}
}

func TestParse_FiltersCorrectly(t *testing.T) {
	now := time.Now()
	future := now.AddDate(10, 0, 0)

	okPem, okFp := makeRoot(t, "Good Root", future)
	emailPem, emailFp := makeRoot(t, "Email Only Root", future)
	distrustPem, distrustFp := makeRoot(t, "Distrusted Root", future)
	expiredPem, expiredFp := makeRoot(t, "Expired Root", now.Add(-time.Hour))

	roots, skipped, err := parse([]map[string]string{
		record("Good Root", "Websites", "", okPem, okFp),
		record("Email Only Root", "Email", "", emailPem, emailFp),
		record("Distrusted Root", "Websites", "2024.11.30", distrustPem, distrustFp),
		record("Expired Root", "Websites", "", expiredPem, expiredFp),
		record("Broken PEM", "Websites", "", "not a pem", ""),
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	if len(roots) != 1 {
		t.Fatalf("남은 루트 %d개 (%v), 기대 1개", len(roots), names(roots))
	}
	if roots[0].name != "Good Root" {
		t.Errorf("남은 루트 = %q", roots[0].name)
	}
	if skipped != 4 {
		t.Errorf("제외 %d개, 기대 4개", skipped)
	}
}

func names(rs []root) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.name)
	}
	return out
}

// 아직 오지 않은 철회 날짜는 걸러내지 않는다.
func TestParse_FutureDistrustKept(t *testing.T) {
	now := time.Now()
	p, fp := makeRoot(t, "Future Distrust", now.AddDate(5, 0, 0))

	roots, _, err := parse([]map[string]string{
		record("Future Distrust", "Websites", now.AddDate(1, 0, 0).Format("2006.01.02"), p, fp),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 {
		t.Errorf("철회 날짜가 미래인데 걸러졌다")
	}
}

// CCADB 지문과 실제 인증서가 어긋나면 생성이 실패해야 한다.
func TestParse_FingerprintMismatch(t *testing.T) {
	p, _ := makeRoot(t, "Tampered", time.Now().AddDate(5, 0, 0))
	_, _, err := parse([]map[string]string{
		record("Tampered", "Websites", "", p, strings.Repeat("A", 64)),
	}, time.Now())
	if err == nil {
		t.Error("지문이 어긋나는데 오류를 반환하지 않았다")
	}
}

// 같은 인증서가 두 번 나오면 한 번만 담는다.
func TestParse_Deduplicates(t *testing.T) {
	p, fp := makeRoot(t, "Dup", time.Now().AddDate(5, 0, 0))
	roots, _, err := parse([]map[string]string{
		record("Dup", "Websites", "", p, fp),
		record("Dup", "Websites;Email", "", p, fp),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 {
		t.Errorf("중복 제거 실패: %d개", len(roots))
	}
}

func TestDisplayName(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "From CN"}}
	if got := displayName(cert, "fallback"); got != "From CN" {
		t.Errorf("CN 우선: %q", got)
	}

	cert = &x509.Certificate{Subject: pkix.Name{Organization: []string{"From O"}}}
	if got := displayName(cert, "fallback"); got != "From O" {
		t.Errorf("CN 이 없으면 O: %q", got)
	}

	cert = &x509.Certificate{}
	if got := displayName(cert, "fallback"); got != "fallback" {
		t.Errorf("둘 다 없으면 CCADB 이름: %q", got)
	}
}

func TestWrite(t *testing.T) {
	p, fp := makeRoot(t, "Write Me", time.Now().AddDate(5, 0, 0))
	roots, _, err := parse([]map[string]string{record("Write Me", "Websites", "", p, fp)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "roots.pem")
	if err := write(out, roots); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"# Write Me", "# SHA-256: " + fp, "BEGIN CERTIFICATE", "직접 고치지 마라"} {
		if !strings.Contains(text, want) {
			t.Errorf("출력에 %q 가 없다", want)
		}
	}

	blk, _ := pem.Decode(data)
	if blk == nil {
		t.Fatal("PEM 을 읽을 수 없다")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Errorf("인증서를 다시 읽을 수 없다: %v", err)
	}

	if err := write(filepath.Join(t.TempDir(), "nodir", "x.pem"), roots); err == nil {
		t.Error("없는 디렉토리인데 오류를 반환하지 않았다")
	}
}

func TestFetchAndRun(t *testing.T) {
	p, fp := makeRoot(t, "Served Root", time.Now().AddDate(5, 0, 0))
	csv := fmt.Sprintf("\"Owner\",\"Common Name or Certificate Name\",\"SHA-256 Fingerprint\",\"Trust Bits\",\"Distrust for TLS After Date\",\"PEM Info\"\n"+
		"\"Test\",\"Served Root\",\"%s\",\"Websites\",\"\",\"'%s'\"\n", fp, p)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			w.WriteHeader(http.StatusInternalServerError)
		case "/empty":
			fmt.Fprint(w, "\"Owner\"\n")
		default:
			fmt.Fprint(w, csv)
		}
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "roots.pem")
	if err := run(srv.URL+"/ok", out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("번들이 생성되지 않았다: %v", err)
	}

	if err := run(srv.URL+"/bad", out); err == nil {
		t.Error("500 응답인데 오류를 반환하지 않았다")
	}
	if err := run(srv.URL+"/empty", out); err == nil {
		t.Error("데이터가 없는데 오류를 반환하지 않았다")
	}
	if err := run("http://127.0.0.1:1/x", out); err == nil {
		t.Error("접속 실패인데 오류를 반환하지 않았다")
	}
}
