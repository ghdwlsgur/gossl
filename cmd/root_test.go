package cmd

import (
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
	}{
		{"버전", []string{"--version"}, 0, "1.2.3"},
		{"도움말", []string{"--help"}, 0, "Available Commands"},
		{"없는 명령", []string{"nosuchcommand"}, 1, ""},
		{"인자가 없는 check", []string{"check"}, 1, ""},
		{"인자가 없는 validate", []string{"validate"}, 1, ""},
		{"split 인자 형식 오류", []string{"split", "show", "extra"}, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut strings.Builder
			code := Run("1.2.3", tc.args, &out, &errOut)

			if code != tc.wantCode {
				t.Errorf("종료 코드 = %d, 기대 %d (stderr=%q)", code, tc.wantCode, errOut.String())
			}
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Errorf("stdout 에 %q 가 없다: %q", tc.wantOut, out.String())
			}
			if tc.wantCode != 0 && errOut.Len() == 0 {
				t.Error("실패인데 stderr 가 비어 있다")
			}
		})
	}
}

// 오류 메시지가 stdout 이 아니라 stderr 로 간다.
func TestRun_ErrorsGoToStderr(t *testing.T) {
	var out, errOut strings.Builder
	if code := Run("dev", []string{"check"}, &out, &errOut); code != 1 {
		t.Fatalf("종료 코드 = %d", code)
	}
	if !strings.Contains(errOut.String(), "[err]") {
		t.Errorf("stderr = %q", errOut.String())
	}
	if strings.Contains(out.String(), "[err]") {
		t.Errorf("오류가 stdout 으로 샜다: %q", out.String())
	}
}

// 버전 문자열이 그대로 전달된다.
func TestRun_VersionInjected(t *testing.T) {
	var out, errOut strings.Builder
	Run("9.9.9-test", []string{"--version"}, &out, &errOut)
	if !strings.Contains(out.String(), "9.9.9-test") {
		t.Errorf("stdout = %q", out.String())
	}
}

// rootCmd 가 전역이라 앞선 호출의 플래그가 남으면 순서에 따라 결과가
// 달라진다. Run 은 몇 번을 불러도 같은 결과를 내야 한다.
func TestRun_IsReentrant(t *testing.T) {
	version := func() string {
		var out, errOut strings.Builder
		if code := Run("7.7.7", []string{"--version"}, &out, &errOut); code != 0 {
			t.Fatalf("종료 코드 = %d", code)
		}
		return out.String()
	}

	first := version()
	if !strings.Contains(first, "7.7.7") {
		t.Fatalf("첫 호출 = %q", first)
	}

	// 사이에 --help 와 실패하는 명령을 끼워 상태를 흐트러뜨린다.
	var o, e strings.Builder
	Run("7.7.7", []string{"--help"}, &o, &e)
	Run("7.7.7", []string{"check"}, &o, &e)

	if again := version(); again != first {
		t.Errorf("재호출 결과가 다르다\n  1회차: %q\n  3회차: %q", first, again)
	}
}
