package main

// 빌드한 실행 파일을 실제로 돌려 확인하는 테스트.
//
// 단위 테스트는 runDownload 같은 함수를 직접 부르므로 그 명령이 cobra
// 트리에 등록됐는지는 검증하지 못한다. 실제로 download 의 init() 이
// 사라졌는데 모든 테스트가 통과한 적이 있다. 여기서는 사용자가 치는
// 것과 같은 방식으로 실행해 종료 코드와 출력 스트림까지 본다.
//
// -cover 로 빌드하므로 os.Exit 이 진짜로 도는 채 Execute 커버리지도 잡힌다.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testVersion = "9.9.9-integration"

var (
	buildOnce sync.Once
	binPath   string
	coverDir  string
	buildErr  error
)

// binary 는 실행 파일을 한 번만 빌드하고 경로를 돌려준다.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gossl-integration-*")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "gossl")

		// CI 는 GOSSL_COVERDIR 로 수집 위치를 지정해 단위 테스트
		// 프로파일과 합친다. 지정이 없으면 임시 디렉토리를 쓴다.
		coverDir = os.Getenv("GOSSL_COVERDIR")
		if coverDir == "" {
			coverDir = filepath.Join(dir, "covdata")
		}
		if err := os.MkdirAll(coverDir, 0o755); err != nil {
			buildErr = err
			return
		}

		cmd := exec.Command("go", "build",
			"-cover",
			"-ldflags", "-X main.gosslVersion="+testVersion,
			"-o", binPath, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = err
			t.Logf("build 출력:\n%s", out)
		}
	})
	if buildErr != nil {
		t.Fatalf("실행 파일 빌드 실패: %v", buildErr)
	}
	return binPath
}

type result struct {
	stdout string
	stderr string
	code   int
}

// runBinary 는 실행 파일을 dir 에서 돌리고 결과를 돌려준다.
func runBinary(t *testing.T, dir string, args ...string) result {
	t.Helper()

	cmd := exec.Command(binary(t), args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOCOVERDIR="+coverDir)

	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("실행 실패: %v", err)
		}
		code = exitErr.ExitCode()
	}
	return result{stdout: out.String(), stderr: errOut.String(), code: code}
}

// 모든 명령이 cobra 트리에 등록돼 있어야 한다.
// init() 이 빠지면 단위 테스트는 통과하지만 이 테스트가 잡는다.
func TestIntegration_AllCommandsRegistered(t *testing.T) {
	if testing.Short() {
		t.Skip("실행 파일 빌드가 필요해 건너뜀")
	}

	got := runBinary(t, t.TempDir(), "--help")
	if got.code != 0 {
		t.Fatalf("--help 종료 코드 = %d, stderr=%s", got.code, got.stderr)
	}

	for _, name := range []string{
		"check", "download", "inspect", "merge",
		"split", "unlock", "unzip", "validate", "zip",
	} {
		if !strings.Contains(got.stdout, name) {
			t.Errorf("--help 에 %q 명령이 없다", name)
		}
		// 실제로 불러도 "unknown command" 가 나오면 안 된다.
		r := runBinary(t, t.TempDir(), name, "--help")
		if strings.Contains(r.stderr, "unknown command") {
			t.Errorf("%q 가 등록되지 않았다: %s", name, strings.TrimSpace(r.stderr))
		}
	}
}

// ldflags 로 주입한 버전이 실제 바이너리에 반영돼야 한다.
func TestIntegration_VersionInjected(t *testing.T) {
	if testing.Short() {
		t.Skip("실행 파일 빌드가 필요해 건너뜀")
	}

	got := runBinary(t, t.TempDir(), "--version")
	if got.code != 0 {
		t.Fatalf("종료 코드 = %d", got.code)
	}
	if !strings.Contains(got.stdout, testVersion) {
		t.Errorf("stdout = %q, %q 를 포함해야 한다", got.stdout, testVersion)
	}
}

// 오류는 stderr 로 가고 stdout 은 비어야 한다. 종료 코드는 1 이다.
func TestIntegration_ErrorStreamAndExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("실행 파일 빌드가 필요해 건너뜀")
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"인자 없는 check", []string{"check"}},
		{"인자 없는 validate", []string{"validate"}},
		{"알 수 없는 명령", []string{"nosuchcommand"}},
		{"split 인자 형식 오류", []string{"split", "notshow", "extra.pem"}},
		{"split 인자 초과", []string{"split", "show", "a", "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runBinary(t, t.TempDir(), tc.args...)

			if got.code != 1 {
				t.Errorf("종료 코드 = %d, 기대 1", got.code)
			}
			if strings.TrimSpace(got.stdout) != "" {
				t.Errorf("오류가 stdout 으로 샜다: %q", got.stdout)
			}
			if strings.TrimSpace(got.stderr) == "" {
				t.Error("stderr 가 비어 있다")
			}
		})
	}
}

// echo 는 inspect 로 이름이 바뀌었지만 별칭으로 계속 받는다.
// 쓰던 사람의 스크립트가 깨지면 안 된다.
func TestIntegration_EchoAliasStillWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("실행 파일 빌드가 필요해 건너뜀")
	}

	got := runBinary(t, t.TempDir(), "echo", "--help")
	if got.code != 0 {
		t.Fatalf("종료 코드 = %d, stderr=%s", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "inspect, echo") {
		t.Errorf("별칭이 표시되지 않는다:\n%s", got.stdout)
	}
}

// 파일을 인자로 주면 프롬프트 없이 끝나야 한다.
// 실행 파일의 stdin 은 /dev/null 이므로, 프롬프트를 타면 반드시 실패한다.
// 파이프라인에서 쓸 수 있다는 주장의 실제 증거가 이것이다.
func TestIntegration_NonInteractive(t *testing.T) {
	if testing.Short() {
		t.Skip("실행 파일 빌드가 필요해 건너뜀")
	}

	dir := t.TempDir()
	root, leaf := testChain(t)
	write := func(name string, ders ...[]byte) {
		t.Helper()
		var out []byte
		for _, d := range ders {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
		}
		if err := os.WriteFile(filepath.Join(dir, name), out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("bundle.pem", leaf, root)
	write("leaf.pem", leaf)
	write("root.pem", root)

	t.Run("inspect", func(t *testing.T) {
		got := runBinary(t, dir, "inspect", "leaf.pem")
		if got.code != 0 {
			t.Fatalf("종료 코드 = %d, stderr=%s", got.code, got.stderr)
		}
	})

	t.Run("split show", func(t *testing.T) {
		got := runBinary(t, dir, "split", "show", "bundle.pem")
		if got.code != 0 {
			t.Fatalf("종료 코드 = %d, stderr=%s", got.code, got.stderr)
		}
		if _, err := os.Stat(filepath.Join(dir, "gossl_leaf_1.crt")); err == nil {
			t.Error("show 인데 파일이 생성됐다")
		}
	})

	t.Run("split", func(t *testing.T) {
		got := runBinary(t, dir, "split", "bundle.pem")
		if got.code != 0 {
			t.Fatalf("종료 코드 = %d, stderr=%s", got.code, got.stderr)
		}
		if _, err := os.Stat(filepath.Join(dir, "gossl_leaf_1.crt")); err != nil {
			t.Error("나뉜 파일이 없다")
		}
	})

	t.Run("merge", func(t *testing.T) {
		got := runBinary(t, dir, "merge", "leaf.pem", "root.pem", "-n", "merged")
		if got.code != 0 {
			t.Fatalf("종료 코드 = %d, stderr=%s", got.code, got.stderr)
		}
		if _, err := os.Stat(filepath.Join(dir, "merged.pem")); err != nil {
			t.Error("합쳐진 파일이 없다")
		}
	})

	// 인자를 주지 않으면 프롬프트를 타므로, 터미널이 없는 지금은 실패해야 한다.
	// 멈춰 있지 않고 끝나는 것이 요점이다.
	t.Run("인자가 없으면 멈추지 않고 실패한다", func(t *testing.T) {
		got := runBinary(t, dir, "split")
		if got.code == 0 {
			t.Error("터미널이 없는데 성공했다")
		}
	})
}

// testChain 은 self-signed root 와 그것이 서명한 leaf 를 만든다.
func testChain(t *testing.T) (root, leaf []byte) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Integration Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root, err = x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(root)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf.integration"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"leaf.integration"},
	}
	leaf, err = x509.CreateCertificate(rand.Reader, leafTpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf
}

// 대상 파일이 없는 디렉토리에서는 안내 메시지와 함께 실패한다.
func TestIntegration_NoCertificateFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("실행 파일 빌드가 필요해 건너뜀")
	}

	got := runBinary(t, t.TempDir(), "inspect")
	if got.code != 1 {
		t.Errorf("종료 코드 = %d, 기대 1", got.code)
	}
	if !strings.Contains(got.stderr, "extension files do not exist") {
		t.Errorf("stderr = %q", got.stderr)
	}
}

// 내장 루트 번들이 실행 파일에 실려 있어야 한다.
func TestIntegration_EmbeddedRootsPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("실행 파일 빌드가 필요해 건너뜀")
	}

	data, err := os.ReadFile(binary(t))
	if err != nil {
		t.Fatal(err)
	}
	// 번들 머리말이 바이너리 안에 있어야 한다.
	if !strings.Contains(string(data), "gossl root certificate bundle") {
		t.Error("루트 인증서 번들이 실행 파일에 실리지 않았다")
	}
}

// 통합 테스트가 끝나면 실행 파일에서 모은 커버리지를 보고한다.
func TestIntegration_ZZReportCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("실행 파일 빌드가 필요해 건너뜀")
	}
	binary(t) // 빌드와 coverDir 보장

	out, err := exec.Command("go", "tool", "covdata", "percent", "-i="+coverDir).CombinedOutput()
	if err != nil {
		t.Logf("커버리지 집계 실패(무시): %v\n%s", err, out)
		return
	}
	t.Logf("실행 파일 커버리지:\n%s", out)
}
