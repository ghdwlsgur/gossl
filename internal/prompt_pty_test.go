package internal

import (
	"testing"
	"time"

	"github.com/AlecAivazis/survey/v2"
	expect "github.com/Netflix/go-expect"
	pseudotty "github.com/creack/pty"
	"github.com/hinshun/vt10x"
)

// withConsole 은 가짜 터미널을 띄우고 surveyPrompter 를 그 위에서 돌린다.
//
// 이렇게 해야 survey 를 직접 호출하는 어댑터를 검증할 수 있다. 프롬프트
// 경계 덕분에 나머지 코드는 가짜 구현으로 테스트하지만, 어댑터 자체는
// 실제 터미널 동작이 필요하다.
func withConsole(t *testing.T, interact func(*expect.Console), run func(surveyPrompter)) {
	t.Helper()

	pty, tty, err := pseudotty.Open()
	if err != nil {
		t.Skipf("pty 를 열 수 없다: %v", err)
	}

	term := vt10x.New(vt10x.WithWriter(tty))
	console, err := expect.NewConsole(
		expect.WithStdin(pty),
		expect.WithStdout(term),
		expect.WithCloser(pty, tty),
	)
	if err != nil {
		t.Fatalf("console 생성 실패: %v", err)
	}
	defer console.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		interact(console)
	}()

	run(surveyPrompter{opts: []survey.AskOpt{
		survey.WithStdio(console.Tty(), console.Tty(), console.Tty()),
	}})

	// 입력 쪽을 닫아 대화 고루틴이 끝나게 한다.
	console.Tty().Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("가짜 터미널 대화가 끝나지 않았다")
	}
}

func TestSurveyPrompter_Select(t *testing.T) {
	var got string
	var err error

	withConsole(t, func(c *expect.Console) {
		c.ExpectString("Pick one")
		// 아래로 한 칸 이동한 뒤 확정한다.
		c.Send("\x1b[B")
		c.SendLine("")
		c.ExpectEOF()
	}, func(p surveyPrompter) {
		got, err = p.Select("Pick one", []string{"alpha", "beta", "gamma"})
	})

	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got != "beta" {
		t.Errorf("Select = %q, 기대 beta (한 칸 아래)", got)
	}
}

func TestSurveyPrompter_SelectFiltersByTyping(t *testing.T) {
	var got string
	var err error

	withConsole(t, func(c *expect.Console) {
		c.ExpectString("Pick one")
		c.SendLine("gam") // 입력으로 목록을 좁힌다
		c.ExpectEOF()
	}, func(p surveyPrompter) {
		got, err = p.Select("Pick one", []string{"alpha", "beta", "gamma"})
	})

	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got != "gamma" {
		t.Errorf("Select = %q, 기대 gamma", got)
	}
}

func TestSurveyPrompter_MultiSelect(t *testing.T) {
	var got []string
	var err error

	withConsole(t, func(c *expect.Console) {
		c.ExpectString("Pick some")
		c.Send(" ")      // 첫 항목 선택
		c.Send("\x1b[B") // 아래로
		c.Send("\x1b[B") // 한 번 더
		c.Send(" ")      // 세 번째 항목 선택
		c.SendLine("")
		c.ExpectEOF()
	}, func(p surveyPrompter) {
		got, err = p.MultiSelect("Pick some", []string{"one", "two", "three"})
	})

	if err != nil {
		t.Fatalf("MultiSelect: %v", err)
	}
	if len(got) != 2 || got[0] != "one" || got[1] != "three" {
		t.Errorf("MultiSelect = %v, 기대 [one three]", got)
	}
}

func TestSurveyPrompter_Input(t *testing.T) {
	var got string
	var err error

	withConsole(t, func(c *expect.Console) {
		c.ExpectString("What is your password")
		c.SendLine("hunter2")
		c.ExpectEOF()
	}, func(p surveyPrompter) {
		got, err = p.Input("What is your password")
	})

	if err != nil {
		t.Fatalf("Input: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Input = %q, 기대 hunter2", got)
	}
}

// 목록이 10개를 넘으면 페이지 크기를 10 으로 제한한다.
func TestSurveyPrompter_SelectLongList(t *testing.T) {
	options := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		options = append(options, string(rune('a'+i)))
	}

	var got string
	var err error
	withConsole(t, func(c *expect.Console) {
		c.ExpectString("Long")
		c.SendLine("")
		c.ExpectEOF()
	}, func(p surveyPrompter) {
		got, err = p.Select("Long", options)
	})

	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got != "a" {
		t.Errorf("Select = %q, 기대 a (첫 항목)", got)
	}
}

// 중단(Ctrl+C) 경로는 여기서 다루지 않는다. survey 가 즉시 반환하면서
// 가짜 터미널의 ExpectEOF 와 경합해 테스트가 멈춘다. 오류가 호출부까지
// 전달되는지는 TestPrompterErrorsPropagate 가 가짜 구현으로 확인한다.
