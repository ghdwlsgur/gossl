package internal

// 과거 코드에서 발견된 버그의 회귀 테스트.
// 각 테스트는 해당 수정이 없으면 실패한다.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCert(t *testing.T, isCA bool, dns []string, cn string, pub, priv any) []byte {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		DNSNames:              dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatalf("인증서 생성 실패: %v", err)
	}
	return der
}

func certPem(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// pemBlockCount++ 가 block == nil 검사보다 앞에 있어 개수가 부풀려졌다.
func TestCountPemBlock(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	one := certPem(newCert(t, false, []string{"a.com"}, "a.com", &k.PublicKey, k))
	two := append(append([]byte{}, one...), one...)

	for _, tc := range []struct {
		name string
		in   []byte
		want int
	}{
		{"빈 입력", nil, 0},
		{"공백만", []byte("\n\n"), 0},
		{"PEM 아닌 내용", []byte("hello"), 0},
		{"블록 1개", one, 1},
		{"블록 1개 + 후행 개행", append(append([]byte{}, one...), '\n'), 1},
		{"블록 1개 + 후행 공백줄", append(append([]byte{}, one...), []byte("\n\n")...), 1},
		{"블록 2개", two, 2},
		{"블록 2개 + 후행 개행", append(append([]byte{}, two...), '\n'), 2},
	} {
		if got := CountPemBlock(tc.in); got != tc.want {
			t.Errorf("%s: CountPemBlock = %d, 기대 %d", tc.name, got, tc.want)
		}
	}
}

// 블록 수가 부풀려지면 정상 단일 인증서가 Unified 로 오인되어 merge 가 거부한다.
func TestDistinguishCertificate_TrailingNewlineIsStillLeaf(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := append(certPem(newCert(t, false, []string{"a.com"}, "a.com", &k.PublicKey, k)), '\n')
	blk, _ := pem.Decode(data)

	detail, err := DistinguishCertificate(&Pem{Type: blk.Type, Data: data, Block: blk}, nil, CountPemBlock(data))
	if err != nil {
		t.Fatal(err)
	}
	if kind := strings.Fields(detail)[0]; kind != "Leaf" {
		t.Errorf("후행 개행이 있는 단일 leaf 인증서를 %q 로 판정 (기대 Leaf). detail=%q", kind, detail)
	}
}

// ECDSA 는 Params().N (곡선 위수) 를 써서 서로 다른 인증서가 같은 해시를 냈다.
func TestGetMd5FromCertificate_EcdsaDistinguishesKeys(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	m1, err := GetMd5FromCertificate(&Pem{Block: &pem.Block{Bytes: newCert(t, false, []string{"a.com"}, "a", &k1.PublicKey, k1)}})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := GetMd5FromCertificate(&Pem{Block: &pem.Block{Bytes: newCert(t, false, []string{"b.com"}, "b", &k2.PublicKey, k2)}})
	if err != nil {
		t.Fatal(err)
	}
	if m1.Certificate == m2.Certificate {
		t.Errorf("서로 다른 ECDSA 공개키가 같은 해시를 냈다: %s", m1.Certificate)
	}
}

// RSA / ECDSA / DSA 외 알고리즘에서 pubKey 가 nil 인 채 역참조되어 패닉했다.
func TestGetMd5FromCertificate_Ed25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m, err := GetMd5FromCertificate(&Pem{Block: &pem.Block{Bytes: newCert(t, false, []string{"ed.com"}, "ed", pub, priv)}})
	if err != nil {
		t.Fatalf("Ed25519 인증서에서 오류: %v", err)
	}
	if m.Certificate == "" {
		t.Error("Ed25519 인증서의 해시가 비어 있다")
	}
}

// GetPemType 은 DER 파일에 Block=nil 을 돌려준다. 그대로 역참조하면 패닉했다.
func TestGetMd5FromCertificate_NilBlock(t *testing.T) {
	if _, err := GetMd5FromCertificate(&Pem{Type: "CRT", Data: []byte("not pem"), Block: nil}); err == nil {
		t.Error("Block 이 nil 인데 오류를 반환하지 않았다")
	}
}

// 같은 쌍이면 인증서와 개인키의 해시가 같아야 도구가 쓸모 있다.
func TestCertificateAndKeyFingerprintsMatch_RSA(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certMd5, err := GetMd5FromCertificate(&Pem{Block: &pem.Block{Bytes: newCert(t, false, []string{"r.com"}, "r", &k.PublicKey, k)}})
	if err != nil {
		t.Fatal(err)
	}
	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	keyMd5, err := GetMd5FromRsaPrivateKey(&Pem{Type: keyBlock.Type, Block: keyBlock})
	if err != nil {
		t.Fatal(err)
	}
	if certMd5.Certificate != keyMd5.RsaPrivateKey {
		t.Errorf("RSA 쌍의 해시가 다르다\n  cert = %s\n  key  = %s", certMd5.Certificate, keyMd5.RsaPrivateKey)
	}
}

// ParsePKCS1PrivateKey 만 써서 PKCS#8 과 SEC1 키를 읽지 못했다.
func TestPrivateKeyFormats(t *testing.T) {
	t.Run("PKCS8 RSA", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		certMd5, err := GetMd5FromCertificate(&Pem{Block: &pem.Block{Bytes: newCert(t, false, []string{"p8.com"}, "p8", &k.PublicKey, k)}})
		if err != nil {
			t.Fatal(err)
		}
		keyBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		keyMd5, err := GetMd5FromRsaPrivateKey(&Pem{Type: keyBlock.Type, Block: keyBlock})
		if err != nil {
			t.Fatalf("PKCS#8 RSA 키를 읽지 못했다: %v", err)
		}
		if certMd5.Certificate != keyMd5.RsaPrivateKey {
			t.Errorf("PKCS#8 RSA 쌍의 해시가 다르다\n  cert = %s\n  key  = %s", certMd5.Certificate, keyMd5.RsaPrivateKey)
		}
	})

	t.Run("SEC1 ECDSA", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		certMd5, err := GetMd5FromCertificate(&Pem{Block: &pem.Block{Bytes: newCert(t, false, []string{"e.com"}, "e", &k.PublicKey, k)}})
		if err != nil {
			t.Fatal(err)
		}
		keyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
		keyMd5, err := GetMd5FromRsaPrivateKey(&Pem{Type: keyBlock.Type, Block: keyBlock})
		if err != nil {
			t.Fatalf("EC 키를 읽지 못했다: %v", err)
		}
		if certMd5.Certificate != keyMd5.RsaPrivateKey {
			t.Errorf("ECDSA 쌍의 해시가 다르다\n  cert = %s\n  key  = %s", certMd5.Certificate, keyMd5.RsaPrivateKey)
		}
	})

	t.Run("무관한 쌍은 달라야 한다", func(t *testing.T) {
		k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(k2)
		certMd5, err := GetMd5FromCertificate(&Pem{Block: &pem.Block{Bytes: newCert(t, false, []string{"x.com"}, "x", &k1.PublicKey, k1)}})
		if err != nil {
			t.Fatal(err)
		}
		keyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
		keyMd5, err := GetMd5FromRsaPrivateKey(&Pem{Type: keyBlock.Type, Block: keyBlock})
		if err != nil {
			t.Fatal(err)
		}
		if certMd5.Certificate == keyMd5.RsaPrivateKey {
			t.Error("무관한 인증서와 키가 일치로 판정됐다")
		}
	})
}

// RSA 해시는 `openssl x509 -noout -modulus | openssl md5` 와 같아야 한다.
// 원본은 openssl 이 포함하는 마지막 개행을 빼먹어 값이 늘 달랐다.
func TestRsaFingerprintMatchesOpenssl(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl 이 없어 건너뜀")
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	gen := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath, "-out", certPath, "-days", "2", "-nodes", "-subj", "/CN=test.local")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("테스트 인증서 생성 실패: %v\n%s", err, out)
	}

	opensslMd5 := func(kind, path string) string {
		t.Helper()
		out, err := exec.Command("openssl", kind, "-noout", "-modulus", "-in", path).Output()
		if err != nil {
			t.Fatalf("openssl %s -modulus 실패: %v", kind, err)
		}
		return md5Hex(out) // 개행 포함 그대로
	}

	certPem, err := GetPemType(certPath)
	if err != nil {
		t.Fatal(err)
	}
	certMd5, err := GetMd5FromCertificate(certPem)
	if err != nil {
		t.Fatal(err)
	}
	if want := opensslMd5("x509", certPath); certMd5.Certificate != want {
		t.Errorf("인증서 해시가 openssl 과 다르다\n  gossl   = %s\n  openssl = %s", certMd5.Certificate, want)
	}

	keyPem, err := GetPemType(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyMd5, err := GetMd5FromRsaPrivateKey(keyPem)
	if err != nil {
		t.Fatal(err)
	}
	if want := opensslMd5("rsa", keyPath); keyMd5.RsaPrivateKey != want {
		t.Errorf("키 해시가 openssl 과 다르다\n  gossl   = %s\n  openssl = %s", keyMd5.RsaPrivateKey, want)
	}
}

// SetTransport 가 만든 DialContext 를 tls.Dial 에 넘기지 않아
// ip 인자가 조용히 무시됐다. 지정한 IP 로 실제로 붙는지 확인한다.
func TestDialTLS_PinsToGivenIP(t *testing.T) {
	if testing.Short() {
		t.Skip("네트워크가 필요해 건너뜀")
	}
	// RFC 5737 TEST-NET-1. 어떤 호스트도 응답하지 않는다.
	conn, err := DialTLS("example.com", "192.0.2.1")
	if err == nil {
		addr := conn.RemoteAddr().String()
		conn.Close()
		t.Errorf("IP 를 고정했는데 %s 에 접속됐다", addr)
	}
}

// SAN 이 없는 CA 인증서에서도 이름 출력이 안전해야 한다.
func TestHostNames(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	leaf, _ := x509.ParseCertificate(newCert(t, false, []string{"a.com", "b.com"}, "a.com", &k.PublicKey, k))
	if got := HostNames(leaf); got != "a.com, b.com" {
		t.Errorf("HostNames = %q, 기대 %q", got, "a.com, b.com")
	}

	ca, _ := x509.ParseCertificate(newCert(t, true, nil, "Test Root CA", &k.PublicKey, k))
	if got := HostNames(ca); got == "" {
		t.Error("SAN 이 없는 인증서에서 빈 문자열을 반환했다")
	}
}

// PKCS#8 이 RSA 가 아니면 타입 단언에서 패닉했다.
func TestPrivateToRsaPrivate_NonRsaReturnsError(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.key")
	if err := PrivateToRsaPrivate(out, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err == nil {
		t.Error("EC 키를 RSA 로 변환하려 했는데 오류를 반환하지 않았다")
	}
}
