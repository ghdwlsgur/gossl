package cmd

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghdwlsgur/gossl/internal"
)

func TestOutputName(t *testing.T) {
	for _, tc := range []struct{ requested, fallback, ext, want string }{
		{"", "default", ".zip", "default.zip"},
		{"  ", "default", ".zip", "default.zip"},
		{"custom", "default", ".zip", "custom.zip"},
		{"  spaced  ", "default", ".pem", "spaced.pem"},
	} {
		if got := outputName(tc.requested, tc.fallback, tc.ext); got != tc.want {
			t.Errorf("outputName(%q) = %q, 기대 %q", tc.requested, got, tc.want)
		}
	}
}

func TestUnzipTarget(t *testing.T) {
	for _, tc := range []struct{ zipName, requested, want string }{
		{"bundle.zip", "", "bundle"},
		{"bundle.zip", "custom", "custom"},
		{"my.certs.2026.zip", "", "my.certs.2026"},
		{"noext", "", "noext"},
	} {
		if got := unzipTarget(tc.zipName, tc.requested); got != tc.want {
			t.Errorf("unzipTarget(%q, %q) = %q, 기대 %q", tc.zipName, tc.requested, got, tc.want)
		}
	}
}

func TestRunZipAndUnzip(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	_, _, leaf := chain(t)
	for _, n := range []string{"a.pem", "b.pem"} {
		if err := os.WriteFile(filepath.Join(dir, n), pemBytes(leaf), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("압축", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{multiSelects: [][]string{{"a.pem", "b.pem"}}})()
		if err := runZip("bundle"); err != nil {
			t.Fatal(err)
		}
		r, err := zip.OpenReader(filepath.Join(dir, "bundle.zip"))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if len(r.File) != 2 {
			t.Errorf("아카이브에 %d개, 기대 2개", len(r.File))
		}
	})

	t.Run("아무것도 고르지 않음", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{multiSelects: [][]string{{}}})()
		if err := runZip("empty"); err == nil {
			t.Error("선택이 없는데 오류를 반환하지 않았다")
		}
	})

	t.Run("해제", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{selects: []string{"bundle.zip"}})()
		if err := runUnzip("extracted"); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"a.pem", "b.pem"} {
			if _, err := os.Stat(filepath.Join(dir, "extracted", n)); err != nil {
				t.Errorf("%s 가 풀리지 않았다", n)
			}
		}
	})

	t.Run("해제 선택 취소", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{err: errTest})()
		if err := runUnzip(""); err == nil {
			t.Error("취소했는데 오류를 반환하지 않았다")
		}
	})
}

func TestRunUnzip_NoZip(t *testing.T) {
	chdir(t, t.TempDir())
	if err := runUnzip(""); err == nil {
		t.Error("zip 이 없는데 오류를 반환하지 않았다")
	}
}

func TestRunUnlock(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	plainDER := x509.MarshalPKCS1PrivateKey(key)

	// 암호가 걸린 레거시 PEM 을 만든다.
	//nolint:staticcheck // SA1019: 테스트 대상이 이 형식이다
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", plainDER, []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Skipf("암호화 PEM 생성 실패: %v", err)
	}
	locked := "locked.key"
	if err := os.WriteFile(filepath.Join(dir, locked), pem.EncodeToMemory(encBlock), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("잘못된 암호", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{selects: []string{locked}, inputs: []string{"wrong"}})()
		if err := runUnlock(); err == nil {
			t.Error("암호가 틀렸는데 오류를 반환하지 않았다")
		}
		// 실패해도 원본이 남아 있어야 한다.
		data, err := os.ReadFile(filepath.Join(dir, locked))
		if err != nil || len(data) == 0 {
			t.Error("실패 후 원본 키가 사라졌다")
		}
	})

	t.Run("암호를 풀어 저장한다", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{selects: []string{locked}, inputs: []string{"secret"}})()
		if err := runUnlock(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, locked))
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(data)
		if blk == nil {
			t.Fatal("PEM 이 아니다")
		}
		//nolint:staticcheck // SA1019
		if x509.IsEncryptedPEMBlock(blk) {
			t.Error("여전히 암호화되어 있다")
		}
		if _, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err != nil {
			t.Errorf("풀린 키를 읽을 수 없다: %v", err)
		}
	})

	t.Run("암호가 걸리지 않은 키", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{selects: []string{locked}})()
		if err := runUnlock(); err == nil {
			t.Error("이미 풀린 키인데 오류를 반환하지 않았다")
		}
	})

	t.Run("인증서를 고르면 거부", func(t *testing.T) {
		_, _, leaf := chain(t)
		if err := os.WriteFile(filepath.Join(dir, "cert.pem"), pemBytes(leaf), 0o600); err != nil {
			t.Fatal(err)
		}
		defer internal.SetPrompter(&fakePrompter{selects: []string{"cert.pem"}})()
		if err := runUnlock(); err == nil {
			t.Error("인증서인데 오류를 반환하지 않았다")
		}
	})
}

func TestRunValidate(t *testing.T) {
	if err := runValidate(nil); err == nil {
		t.Error("도메인이 없는데 오류를 반환하지 않았다")
	}
	if err := runValidate([]string{"this-domain-does-not-exist.invalid"}); err == nil {
		t.Error("없는 도메인인데 오류를 반환하지 않았다")
	}
	if testing.Short() {
		return
	}
	if err := runValidate([]string{"example.com"}); err != nil {
		t.Errorf("runValidate: %v", err)
	}
}
