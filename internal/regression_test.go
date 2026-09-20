package internal

// 과거 코드에서 발견된 버그의 회귀 테스트.
// 각 테스트는 해당 수정이 없으면 실패한다.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
