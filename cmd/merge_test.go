package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghdwlsgur/gossl/internal"
)

func TestIsPrivateKeyBlock(t *testing.T) {
	for _, tc := range []struct {
		pemType string
		want    bool
	}{
		{"RSA PRIVATE KEY", true},
		{"PRIVATE KEY", true},    // PKCS#8
		{"EC PRIVATE KEY", true}, // SEC1
		{"CERTIFICATE", false},
		{"CERTIFICATE REQUEST", false},
		{"PUBLIC KEY", false},
	} {
		if got := isPrivateKeyBlock(tc.pemType); got != tc.want {
			t.Errorf("isPrivateKeyBlock(%q) = %v, 기대 %v", tc.pemType, got, tc.want)
		}
	}
}

// 인증서 파일과 개인키 파일을 임시 디렉토리에 만든다.
func mergeFixtures(t *testing.T, dir string) (leafPath, interPath, rootPath, keyPath string) {
	t.Helper()
	root, inter, leaf := chain(t)

	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return name
	}

	leafPath = write("leaf.pem", pemBytes(leaf))
	interPath = write("inter.pem", pemBytes(inter))
	rootPath = write("root.pem", pemBytes(root))

	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return
}

func TestCollectForMerge(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	leaf, inter, root, key := mergeFixtures(t, dir)

	t.Run("종류별로 모은다", func(t *testing.T) {
		l, i, r, p, err := collectForMerge([]string{leaf, inter, root}, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(l) != 1 || len(i) != 1 || len(r) != 1 || len(p) != 0 {
			t.Errorf("leaf=%d inter=%d root=%d private=%d", len(l), len(i), len(r), len(p))
		}
	})

	// PKCS#8 키는 타입이 "PRIVATE KEY" 다. 예전에는 "RSA PRIVATE KEY" 만
	// 검사해서 이 키가 인증서 파일로 오인됐다.
	t.Run("PKCS8 개인키를 거부한다", func(t *testing.T) {
		_, _, _, _, err := collectForMerge([]string{leaf, key}, false)
		if err == nil {
			t.Fatal("개인키가 섞였는데 오류를 반환하지 않았다")
		}
		if got := err.Error(); got != "please select only the certificate file" {
			t.Errorf("오류 메시지 = %q", got)
		}
	})

	t.Run("force 면 개인키를 받는다", func(t *testing.T) {
		_, _, _, p, err := collectForMerge([]string{leaf, key}, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 1 {
			t.Errorf("private %d개, 기대 1개", len(p))
		}
	})

	t.Run("이미 병합된 파일은 거부한다", func(t *testing.T) {
		r2, i2, l2 := chain(t)
		bundle := "bundle.pem"
		if err := os.WriteFile(filepath.Join(dir, bundle), pemBytes(l2, i2, r2), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := collectForMerge([]string{bundle}, false); err == nil {
			t.Error("통합 파일인데 오류를 반환하지 않았다")
		}
	})

	t.Run("빈 파일", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(dir, "empty.pem"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := collectForMerge([]string{"empty.pem"}, false); err == nil {
			t.Error("빈 파일인데 오류를 반환하지 않았다")
		}
	})

	t.Run("없는 파일", func(t *testing.T) {
		if _, _, _, _, err := collectForMerge([]string{"nope.pem"}, false); err == nil {
			t.Error("없는 파일인데 오류를 반환하지 않았다")
		}
	})
}

func TestWriteMerged(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	leaf, inter, root, _ := mergeFixtures(t, dir)

	l, i, r, p, err := collectForMerge([]string{leaf, inter, root}, false)
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "merged.pem")
	if err := writeMerged(out, l, i, r, p); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if n := internal.CountPemBlock(data); n != 3 {
		t.Errorf("병합 결과 블록 %d개, 기대 3개", n)
	}

	// 순서가 leaf -> intermediate -> root 여야 한다.
	first, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(first.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "leaf.test" {
		t.Errorf("첫 블록 = %q, leaf 가 먼저 와야 한다", cert.Subject.CommonName)
	}
}

func TestRunMerge(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	mergeFixtures(t, dir)

	t.Run("두 개 미만 선택", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{multiSelects: [][]string{{"leaf.pem"}}})()
		if err := runMerge("", false); err == nil {
			t.Error("하나만 골랐는데 오류를 반환하지 않았다")
		}
	})

	t.Run("네 개 초과 선택", func(t *testing.T) {
		five := []string{"a", "b", "c", "d", "e"}
		defer internal.SetPrompter(&fakePrompter{multiSelects: [][]string{five}})()
		if err := runMerge("", false); err == nil {
			t.Error("다섯 개를 골랐는데 오류를 반환하지 않았다")
		}
	})

	t.Run("정상 병합", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{
			multiSelects: [][]string{{"leaf.pem", "inter.pem", "root.pem"}},
		})()
		if err := runMerge("chain", false); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "chain.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if n := internal.CountPemBlock(data); n != 3 {
			t.Errorf("블록 %d개, 기대 3개", n)
		}
	})

	t.Run("이름을 주지 않으면 기본값", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{
			multiSelects: [][]string{{"leaf.pem", "inter.pem"}},
		})()
		if err := runMerge("", false); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "gossl_merge_output.pem")); err != nil {
			t.Error("기본 이름으로 생성되지 않았다")
		}
	})
}
