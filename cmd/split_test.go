package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghdwlsgur/gossl/internal"
)

// chain 은 root -> intermediate -> leaf 로 이어지는 3단 체인을 만든다.
func chain(t *testing.T) (root, inter, leaf []byte) {
	t.Helper()

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(root)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	inter, err = x509.CreateCertificate(rand.Reader, interTpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, _ := x509.ParseCertificate(inter)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"leaf.test"},
	}
	leaf, err = x509.CreateCertificate(rand.Reader, leafTpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	return root, inter, leaf
}

func pemBytes(ders ...[]byte) []byte {
	var out []byte
	for _, d := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return out
}

func TestClassifyBlocks(t *testing.T) {
	root, inter, leaf := chain(t)

	c, err := classifyBlocks(pemBytes(leaf, inter, root))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.leaf) != 1 {
		t.Errorf("leaf %d개, 기대 1개", len(c.leaf))
	}
	if len(c.intermediate) != 1 {
		t.Errorf("intermediate %d개, 기대 1개", len(c.intermediate))
	}
	if len(c.root) != 1 {
		t.Errorf("root %d개, 기대 1개", len(c.root))
	}

	// 각 종류마다 [Subject CN, Issuer CN] 두 개가 쌓인다.
	if len(c.leafSubIss) != 2 || c.leafSubIss[0] != "leaf.test" {
		t.Errorf("leafSubIss = %v", c.leafSubIss)
	}
}

func TestClassifyBlocks_Empty(t *testing.T) {
	c, err := classifyBlocks(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.leaf)+len(c.intermediate)+len(c.root) != 0 {
		t.Error("빈 입력인데 블록이 잡혔다")
	}
}

func TestClassifyBlocks_Invalid(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	if _, err := classifyBlocks(bad); err == nil {
		t.Error("파싱 불가한 인증서인데 오류를 반환하지 않았다")
	}
}

func TestChainLinked(t *testing.T) {
	for _, tc := range []struct {
		name             string
		lower, upper     []string
		linked, testable bool
	}{
		{"이어짐", []string{"leaf", "Root CA"}, []string{"Root CA", "Root CA"}, true, true},
		{"끊어짐", []string{"leaf", "Other CA"}, []string{"Root CA", "Root CA"}, false, true},
		{"아래가 비었다", nil, []string{"Root CA"}, false, false},
		{"위가 비었다", []string{"leaf", "CA"}, nil, false, false},
	} {
		linked, ok := chainLinked(tc.lower, tc.upper)
		if linked != tc.linked || ok != tc.testable {
			t.Errorf("%s: chainLinked = (%v, %v), 기대 (%v, %v)", tc.name, linked, ok, tc.linked, tc.testable)
		}
	}
}

func TestWriteBlocks(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	root, inter, leaf := chain(t)
	c, err := classifyBlocks(pemBytes(leaf, inter, root))
	if err != nil {
		t.Fatal(err)
	}

	if err := writeBlocks(c.leaf, "leaf"); err != nil {
		t.Fatal(err)
	}
	if err := writeBlocks(c.intermediate, "intermediate"); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"gossl_leaf_1.crt", "gossl_intermediate_1.crt"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s 가 없다: %v", name, err)
			continue
		}
		if blk, _ := pem.Decode(data); blk == nil || blk.Type != "CERTIFICATE" {
			t.Errorf("%s 의 내용이 인증서가 아니다", name)
		}
	}

	// 빈 목록은 아무 파일도 만들지 않는다.
	if err := writeBlocks(nil, "root"); err != nil {
		t.Errorf("빈 목록에서 오류: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "gossl_root_1.crt")); err == nil {
		t.Error("빈 목록인데 파일이 생성됐다")
	}
}

func TestSplittableFiles(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	root, inter, leaf := chain(t)

	// 블록 3개짜리 통합 파일과 블록 1개짜리 파일을 둔다.
	if err := os.WriteFile(filepath.Join(dir, "bundle.pem"), pemBytes(leaf, inter, root), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "single.pem"), pemBytes(leaf), 0o600); err != nil {
		t.Fatal(err)
	}

	list, err := splittableFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("고른 파일 = %v, 통합 파일 하나만 와야 한다", list)
	}
	if want := "bundle.pem [in 3 Block]"; list[0] != want {
		t.Errorf("항목 = %q, 기대 %q", list[0], want)
	}
}

func TestSplittableFiles_None(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	_, _, leaf := chain(t)
	if err := os.WriteFile(filepath.Join(dir, "single.pem"), pemBytes(leaf), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := splittableFiles(); err == nil {
		t.Error("쪼갤 파일이 없는데 오류를 반환하지 않았다")
	}
}

func TestRunSplit(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	root, inter, leaf := chain(t)
	if err := os.WriteFile(filepath.Join(dir, "bundle.pem"), pemBytes(leaf, inter, root), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("show 는 파일을 만들지 않는다", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{selects: []string{"bundle.pem [in 3 Block]"}})()
		if err := runSplit(true, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "gossl_leaf_1.crt")); err == nil {
			t.Error("show 인데 파일이 생성됐다")
		}
	})

	t.Run("종류별로 파일을 만든다", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{selects: []string{"bundle.pem [in 3 Block]"}})()
		if err := runSplit(false, ""); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"gossl_leaf_1.crt", "gossl_intermediate_1.crt", "gossl_root_1.crt"} {
			if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
				t.Errorf("%s 가 없다", n)
			}
		}
	})

	t.Run("선택 취소", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{err: errTest})()
		if err := runSplit(false, ""); err == nil {
			t.Error("취소했는데 오류를 반환하지 않았다")
		}
	})
}
