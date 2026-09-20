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
