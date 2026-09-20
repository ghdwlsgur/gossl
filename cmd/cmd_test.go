package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghdwlsgur/gossl/internal"
)

// fakePrompter 는 미리 정한 답을 순서대로 돌려준다.
type fakePrompter struct {
	selects      []string
	multiSelects [][]string
	inputs       []string
	err          error
	asked        []string
}

func (f *fakePrompter) Select(message string, _ []string) (string, error) {
	f.asked = append(f.asked, message)
	if f.err != nil {
		return "", f.err
	}
	if len(f.selects) == 0 {
		return "", errors.New("Select 답이 소진됐다")
	}
	a := f.selects[0]
	f.selects = f.selects[1:]
	return a, nil
}

func (f *fakePrompter) MultiSelect(message string, _ []string) ([]string, error) {
	f.asked = append(f.asked, message)
	if f.err != nil {
		return nil, f.err
	}
	if len(f.multiSelects) == 0 {
		return nil, errors.New("MultiSelect 답이 소진됐다")
	}
	a := f.multiSelects[0]
	f.multiSelects = f.multiSelects[1:]
	return a, nil
}

func (f *fakePrompter) Input(message string) (string, error) {
	f.asked = append(f.asked, message)
	if f.err != nil {
		return "", f.err
	}
	if len(f.inputs) == 0 {
		return "", errors.New("Input 답이 소진됐다")
	}
	a := f.inputs[0]
	f.inputs = f.inputs[1:]
	return a, nil
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func TestSetDomain(t *testing.T) {
	if _, err := setDomain(nil); err == nil {
		t.Error("인자가 없는데 오류를 반환하지 않았다")
	}
	if _, err := setDomain([]string{""}); err == nil {
		t.Error("빈 문자열인데 오류를 반환하지 않았다")
	}
	got, err := setDomain([]string{"example.com", "extra"})
	if err != nil || got != "example.com" {
		t.Errorf("setDomain = %q, %v", got, err)
	}
}

func TestPanicRed(t *testing.T) {
	err := panicRed(errors.New("무언가 잘못됨"))
	if err == nil {
		t.Fatal("nil 을 반환했다")
	}
	if !strings.Contains(err.Error(), "무언가 잘못됨") {
		t.Errorf("원래 메시지가 없다: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "[err]") {
		t.Errorf("[err] 접두가 없다: %q", err.Error())
	}
}

func TestRunCheck_Errors(t *testing.T) {
	if err := runCheck(nil); err == nil {
		t.Error("도메인이 없는데 오류를 반환하지 않았다")
	}
	if err := runCheck([]string{"this-domain-does-not-exist.invalid"}); err == nil {
		t.Error("없는 도메인인데 오류를 반환하지 않았다")
	}
}

func TestRunCheck_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("네트워크가 필요해 건너뜀")
	}
	if err := runCheck([]string{"example.com"}); err != nil {
		t.Errorf("runCheck: %v", err)
	}
}

func TestRunDownload(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	t.Run("선택한 인증서를 내려받는다", func(t *testing.T) {
		if testing.Short() {
			t.Skip("네트워크가 필요해 건너뜀")
		}
		fake := &fakePrompter{selects: []string{"DigiCert Global Root G2"}}
		defer internal.SetPrompter(fake)()

		if err := runDownload(); err != nil {
			t.Fatalf("runDownload: %v", err)
		}
		// 이름의 공백을 지운 파일명으로 저장된다.
		want := filepath.Join(dir, "DigiCertGlobalRootG2.pem")
		if _, err := os.Stat(want); err != nil {
			t.Errorf("받은 파일이 없다: %s", want)
		}
		if len(fake.asked) != 1 || !strings.Contains(fake.asked[0], "root certificate") {
			t.Errorf("질문 내용 = %v", fake.asked)
		}
	})

	t.Run("사용자가 취소하면 오류", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{err: errors.New("취소됨")})()
		if err := runDownload(); err == nil {
			t.Error("취소했는데 오류를 반환하지 않았다")
		}
	})

	t.Run("목록에 없는 이름을 고르면 오류", func(t *testing.T) {
		defer internal.SetPrompter(&fakePrompter{selects: []string{"존재하지 않는 CA"}})()
		// FindURL 이 "No Data" 를 돌려주고 다운로드가 실패해야 한다.
		if err := runDownload(); err == nil {
			t.Error("잘못된 선택인데 오류를 반환하지 않았다")
		}
	})
}
