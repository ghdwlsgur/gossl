package internal

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootCertificates(t *testing.T) {
	roots, err := RootCertificates()
	if err != nil {
		t.Fatalf("내장 번들을 읽지 못했다: %v", err)
	}
	if len(roots) < 100 {
		t.Errorf("루트 %d개, 100개 이상이어야 한다", len(roots))
	}

	now := time.Now()
	seen := map[string]bool{}
	for _, r := range roots {
		if r.Name == "" {
			t.Errorf("이름이 빈 루트가 있다 (%s)", r.Fingerprint)
		}
		if r.Certificate == nil {
			t.Fatalf("%s: 인증서가 nil", r.Name)
		}

		// 번들은 TLS 용, 미만료, 자기 서명 루트만 담아야 한다.
		if !r.Certificate.IsCA {
			t.Errorf("%s: CA 가 아니다", r.Name)
		}
		if now.After(r.Certificate.NotAfter) {
			t.Errorf("%s: 이미 만료됐다 (%s)", r.Name, r.Certificate.NotAfter.Format("2006-01-02"))
		}
		if !isSelfSigned(r.Certificate) {
			t.Errorf("%s: 자기 서명이 아니다", r.Name)
		}

		// 지문은 인증서에서 다시 계산되므로 항상 맞아야 한다.
		sum := sha256.Sum256(r.Certificate.Raw)
		if want := strings.ToUpper(hex.EncodeToString(sum[:])); r.Fingerprint != want {
			t.Errorf("%s: 지문 불일치", r.Name)
		}
		if seen[r.Fingerprint] {
			t.Errorf("%s: 중복된 인증서", r.Name)
		}
		seen[r.Fingerprint] = true

		// PEM 은 다시 파싱 가능해야 한다.
		blk, _ := pem.Decode(r.PEM)
		if blk == nil {
			t.Errorf("%s: PEM 이 유효하지 않다", r.Name)
			continue
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			t.Errorf("%s: PEM 을 다시 읽을 수 없다: %v", r.Name, err)
		}
	}

	// 이름순으로 정렬돼 있어야 한다.
	for i := 1; i < len(roots); i++ {
		if roots[i-1].Name > roots[i].Name {
			t.Errorf("정렬이 깨졌다: %q 뒤에 %q", roots[i-1].Name, roots[i].Name)
			break
		}
	}
}

func TestRootCertificateNames(t *testing.T) {
	names, err := RootCertificateNames()
	if err != nil {
		t.Fatal(err)
	}
	roots, _ := RootCertificates()
	if len(names) != len(roots) {
		t.Errorf("이름 %d개, 루트 %d개", len(names), len(roots))
	}
}

func TestFindRootCertificate(t *testing.T) {
	names, err := RootCertificateNames()
	if err != nil {
		t.Fatal(err)
	}

	got, err := FindRootCertificate(names[0])
	if err != nil {
		t.Fatalf("첫 항목을 찾지 못했다: %v", err)
	}
	if got.Name != names[0] {
		t.Errorf("이름 = %q, 기대 %q", got.Name, names[0])
	}

	if _, err := FindRootCertificate("존재하지 않는 루트 CA"); err == nil {
		t.Error("없는 이름인데 오류를 반환하지 않았다")
	}
}

// 잘 알려진 루트가 번들에 들어 있어야 한다.
func TestWellKnownRootsPresent(t *testing.T) {
	names, err := RootCertificateNames()
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for _, want := range []string{
		"DigiCert Global Root G2",
		"ISRG Root X1", // Let's Encrypt
		"GlobalSign",
	} {
		if !set[want] {
			t.Errorf("%q 가 번들에 없다", want)
		}
	}
}

// 신뢰가 철회되거나 만료된 루트는 빠져 있어야 한다.
func TestDistrustedRootsAbsent(t *testing.T) {
	names, err := RootCertificateNames()
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for _, gone := range []string{
		"AddTrust External CA Root",  // 2020 만료
		"GTE CyberTrust Global Root", // 2018 만료
		"Baltimore CyberTrust Root",  // 2025 만료
	} {
		if set[gone] {
			t.Errorf("%q 는 더 이상 유효하지 않은데 번들에 있다", gone)
		}
	}
}

func TestSaveRootCertificate(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	names, _ := RootCertificateNames()
	root, err := FindRootCertificate(names[0])
	if err != nil {
		t.Fatal(err)
	}

	path, err := SaveRootCertificate(root, "saved.pem")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		t.Fatal("저장된 파일이 PEM 이 아니다")
	}

	// 상위 경로로 빠져나가지 못한다.
	if _, err := SaveRootCertificate(root, "../escaped.pem"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped.pem")); err != nil {
		t.Error("파일명만 취해 현재 디렉토리에 저장돼야 한다")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escaped.pem")); err == nil {
		t.Error("상위 디렉토리에 파일이 생성됐다")
	}

	if _, err := SaveRootCertificate(root, "/"); err == nil {
		t.Error("경로 구분자만 준 경우 오류여야 한다")
	}
}

func TestParseRootBundle_Errors(t *testing.T) {
	if _, err := parseRootBundle(nil); err == nil {
		t.Error("빈 번들인데 오류를 반환하지 않았다")
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	if _, err := parseRootBundle(bad); err == nil {
		t.Error("파싱 불가한 인증서인데 오류를 반환하지 않았다")
	}
}
