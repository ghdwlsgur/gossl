package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghdwlsgur/gossl/internal"
)

// noPrompt 는 어떤 프롬프트도 실패시키는 프롬프터를 건다.
// 인자를 준 경로가 정말 프롬프트를 건너뛰는지 보려면 이렇게 해야 한다.
// 프롬프트를 한 번이라도 타면 테스트가 실패한다.
func noPrompt(t *testing.T) *fakePrompter {
	t.Helper()
	f := &fakePrompter{err: errTest}
	t.Cleanup(internal.SetPrompter(f))
	return f
}

// assertNotAsked 는 프롬프트가 아예 뜨지 않았는지 확인한다.
func assertNotAsked(t *testing.T, f *fakePrompter) {
	t.Helper()
	if len(f.asked) != 0 {
		t.Errorf("프롬프트가 떴다: %v", f.asked)
	}
}

func TestStatCertFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.pem")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := statCertFile(file); err != nil {
		t.Errorf("정상 파일인데 오류: %v", err)
	}
	if err := statCertFile(dir); err == nil {
		t.Error("디렉토리인데 오류를 반환하지 않았다")
	}
	if err := statCertFile(filepath.Join(dir, "없음.pem")); err == nil {
		t.Error("없는 파일인데 오류를 반환하지 않았다")
	}
}

func TestResolveCertFile_SkipsPromptWhenNamed(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := noPrompt(t)
	c, name, err := resolveCertFile("물어보면 안 된다", "server.crt")
	if err != nil {
		t.Fatalf("이름을 줬는데 실패했다: %v", err)
	}
	assertNotAsked(t, f)

	if name != "server.crt" {
		t.Errorf("name = %q", name)
	}
	if c.Extension != "crt" {
		t.Errorf("Extension = %q, 기대 crt", c.Extension)
	}
}

func TestRunInspect_FileArgument(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	_, _, leaf := chain(t)
	if err := os.WriteFile(filepath.Join(dir, "leaf.pem"), pemBytes(leaf), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("프롬프트 없이 읽는다", func(t *testing.T) {
		f := noPrompt(t)
		if err := runInspect("leaf.pem", false); err != nil {
			t.Fatalf("runInspect: %v", err)
		}
		assertNotAsked(t, f)
	})

	t.Run("없는 파일은 실패한다", func(t *testing.T) {
		noPrompt(t)
		if err := runInspect("없음.pem", false); err == nil {
			t.Error("없는 파일인데 오류를 반환하지 않았다")
		}
	})
}

// 파일을 인자로 받으면 변환 여부를 물을 수 없으므로 묻지 않아야 한다.
func TestRunInspect_PrivateKeyConversion(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	name := "pkcs8.key"
	original := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, name), original, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("플래그가 없으면 변환하지 않는다", func(t *testing.T) {
		f := noPrompt(t)
		if err := runInspect(name, false); err != nil {
			t.Fatalf("runInspect: %v", err)
		}
		assertNotAsked(t, f)

		after, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(original) {
			t.Error("--convert 없이 파일이 바뀌었다")
		}
	})

	t.Run("--convert 면 묻지 않고 변환한다", func(t *testing.T) {
		f := noPrompt(t)
		if err := runInspect(name, true); err != nil {
			t.Fatalf("runInspect: %v", err)
		}
		assertNotAsked(t, f)

		after, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(after)
		if blk == nil || blk.Type != "RSA PRIVATE KEY" {
			t.Errorf("변환되지 않았다: %v", blk)
		}
	})
}

func TestInspectConvertMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		file    string
		convert bool
		want    convertMode
	}{
		{"대화형은 묻는다", "", false, convertAsk},
		{"파일 인자는 묻지 않는다", "a.pem", false, convertNever},
		{"--convert 는 변환한다", "a.pem", true, convertAlways},
		{"대화형 + --convert", "", true, convertAlways},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := inspectConvertMode(tc.file, tc.convert); got != tc.want {
				t.Errorf("= %v, 기대 %v", got, tc.want)
			}
		})
	}
}

func TestParseSplitArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		showOnly bool
		file     string
		wantErr  bool
	}{
		{"인자 없음", nil, false, "", false},
		{"show 만", []string{"show"}, true, "", false},
		{"파일만", []string{"b.pem"}, false, "b.pem", false},
		{"show + 파일", []string{"show", "b.pem"}, true, "b.pem", false},
		{"두 번째 자리에 show 가 아닌 것", []string{"x", "b.pem"}, false, "", true},
		{"인자가 너무 많다", []string{"show", "a", "b"}, false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			showOnly, file, err := parseSplitArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("오류를 반환하지 않았다")
				}
				return
			}
			if err != nil {
				t.Fatalf("예상치 못한 오류: %v", err)
			}
			if showOnly != tc.showOnly || file != tc.file {
				t.Errorf("= (%v, %q), 기대 (%v, %q)", showOnly, file, tc.showOnly, tc.file)
			}
		})
	}
}

func TestRunSplit_FileArgument(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	root, inter, leaf := chain(t)
	if err := os.WriteFile(filepath.Join(dir, "bundle.pem"), pemBytes(leaf, inter, root), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "single.pem"), pemBytes(leaf), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("프롬프트 없이 나눈다", func(t *testing.T) {
		f := noPrompt(t)
		if err := runSplit(false, "bundle.pem"); err != nil {
			t.Fatalf("runSplit: %v", err)
		}
		assertNotAsked(t, f)

		for _, n := range []string{"gossl_leaf_1.crt", "gossl_intermediate_1.crt", "gossl_root_1.crt"} {
			if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
				t.Errorf("%s 가 없다", n)
			}
		}
	})

	t.Run("show 는 파일을 만들지 않는다", func(t *testing.T) {
		f := noPrompt(t)
		if err := runSplit(true, "bundle.pem"); err != nil {
			t.Fatalf("runSplit: %v", err)
		}
		assertNotAsked(t, f)
	})

	t.Run("블록이 하나면 거부한다", func(t *testing.T) {
		noPrompt(t)
		if err := runSplit(false, "single.pem"); err == nil {
			t.Error("블록이 하나인데 오류를 반환하지 않았다")
		}
	})

	t.Run("없는 파일은 실패한다", func(t *testing.T) {
		noPrompt(t)
		if err := runSplit(false, "없음.pem"); err == nil {
			t.Error("없는 파일인데 오류를 반환하지 않았다")
		}
	})
}

func TestRunMerge_FileArguments(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	root, inter, leaf := chain(t)
	for name, der := range map[string][]byte{
		"leaf.pem":  leaf,
		"inter.pem": inter,
		"root.pem":  root,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pemBytes(der), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("프롬프트 없이 합친다", func(t *testing.T) {
		f := noPrompt(t)
		err := runMerge([]string{"leaf.pem", "inter.pem", "root.pem"}, "chain", false)
		if err != nil {
			t.Fatalf("runMerge: %v", err)
		}
		assertNotAsked(t, f)

		data, err := os.ReadFile(filepath.Join(dir, "chain.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if n := internal.CountPemBlock(data); n != 3 {
			t.Errorf("블록 %d개, 기대 3개", n)
		}
	})

	t.Run("하나만 주면 거부한다", func(t *testing.T) {
		noPrompt(t)
		if err := runMerge([]string{"leaf.pem"}, "", false); err == nil {
			t.Error("한 개인데 오류를 반환하지 않았다")
		}
	})

	t.Run("없는 파일은 실패한다", func(t *testing.T) {
		noPrompt(t)
		if err := runMerge([]string{"leaf.pem", "없음.pem"}, "", false); err == nil {
			t.Error("없는 파일인데 오류를 반환하지 않았다")
		}
	})
}

func TestResolvePassword(t *testing.T) {
	dir := t.TempDir()

	t.Run("password-file", func(t *testing.T) {
		path := filepath.Join(dir, "pw.txt")
		// echo 로 만든 파일처럼 끝에 개행이 붙어도 그대로 읽으면 안 된다.
		if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolvePassword(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != "secret" {
			t.Errorf("= %q, 기대 %q", got, "secret")
		}
	})

	t.Run("없는 password-file", func(t *testing.T) {
		if _, err := resolvePassword(filepath.Join(dir, "없음")); err == nil {
			t.Error("오류를 반환하지 않았다")
		}
	})

	t.Run("GOSSL_PASSWORD", func(t *testing.T) {
		t.Setenv("GOSSL_PASSWORD", "from-env")
		got, err := resolvePassword("")
		if err != nil {
			t.Fatal(err)
		}
		if got != "from-env" {
			t.Errorf("= %q", got)
		}
	})

	t.Run("password-file 이 환경변수보다 우선한다", func(t *testing.T) {
		t.Setenv("GOSSL_PASSWORD", "from-env")
		path := filepath.Join(dir, "pw2.txt")
		if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolvePassword(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != "from-file" {
			t.Errorf("= %q", got)
		}
	})

	t.Run("입력원이 없을 때", func(t *testing.T) {
		if stdinIsTerminal() {
			defer internal.SetPrompter(&fakePrompter{inputs: []string{"typed"}})()
			got, err := resolvePassword("")
			if err != nil {
				t.Fatal(err)
			}
			if got != "typed" {
				t.Errorf("= %q", got)
			}
			return
		}
		// 터미널이 없으면 멈춰 있지 말고 실패해야 한다.
		if _, err := resolvePassword(""); err == nil {
			t.Error("터미널이 없는데 오류를 반환하지 않았다")
		}
	})
}

func TestRunUnlock_NonInteractive(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // SA1019: 테스트 대상이 이 형식이다
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(key), []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Skipf("암호화 PEM 생성 실패: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "locked.key"), pem.EncodeToMemory(encBlock), 0o600); err != nil {
		t.Fatal(err)
	}

	pwFile := filepath.Join(dir, "pw.txt")
	if err := os.WriteFile(pwFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := noPrompt(t)
	if err := runUnlock("locked.key", pwFile); err != nil {
		t.Fatalf("runUnlock: %v", err)
	}
	assertNotAsked(t, f)

	data, err := os.ReadFile(filepath.Join(dir, "locked.key"))
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
}
