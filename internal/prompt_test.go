package internal

import (
	"errors"
	"testing"

	"github.com/AlecAivazis/survey/v2"
)

// FakePrompter 는 미리 정한 답을 순서대로 돌려준다.
// 테스트에서 SetPrompter 로 끼워 넣는다.
type FakePrompter struct {
	Selects      []string
	MultiSelects [][]string
	Inputs       []string
	Err          error

	// 어떤 질문을 받았는지 기록한다.
	AskedMessages []string
	AskedOptions  [][]string
}

func (f *FakePrompter) record(message string, options []string) {
	f.AskedMessages = append(f.AskedMessages, message)
	f.AskedOptions = append(f.AskedOptions, options)
}

func (f *FakePrompter) Select(message string, options []string) (string, error) {
	f.record(message, options)
	if f.Err != nil {
		return "", f.Err
	}
	if len(f.Selects) == 0 {
		return "", errors.New("FakePrompter: Select 답이 소진됐다")
	}
	answer := f.Selects[0]
	f.Selects = f.Selects[1:]
	return answer, nil
}

func (f *FakePrompter) MultiSelect(message string, options []string) ([]string, error) {
	f.record(message, options)
	if f.Err != nil {
		return nil, f.Err
	}
	if len(f.MultiSelects) == 0 {
		return nil, errors.New("FakePrompter: MultiSelect 답이 소진됐다")
	}
	answer := f.MultiSelects[0]
	f.MultiSelects = f.MultiSelects[1:]
	return answer, nil
}

func (f *FakePrompter) Input(message string) (string, error) {
	f.record(message, nil)
	if f.Err != nil {
		return "", f.Err
	}
	if len(f.Inputs) == 0 {
		return "", errors.New("FakePrompter: Input 답이 소진됐다")
	}
	answer := f.Inputs[0]
	f.Inputs = f.Inputs[1:]
	return answer, nil
}

func TestPrompterBoundary(t *testing.T) {
	fake := &FakePrompter{
		Selects:      []string{"chosen"},
		MultiSelects: [][]string{{"a", "b"}},
		Inputs:       []string{"typed"},
	}
	defer SetPrompter(fake)()

	got, err := AskSelect("하나 고르세요", []string{"chosen", "other"})
	if err != nil || got != "chosen" {
		t.Errorf("AskSelect = %q, %v", got, err)
	}

	list, err := AskMultiSelect("여러 개 고르세요", []string{"a", "b", "c"})
	if err != nil || len(list) != 2 {
		t.Errorf("AskMultiSelect = %v, %v", list, err)
	}

	in, err := AskInput("입력하세요", 1)
	if err != nil || in != "typed" {
		t.Errorf("AskInput = %q, %v", in, err)
	}

	if len(fake.AskedMessages) != 3 {
		t.Errorf("질문 %d회 기록, 기대 3회", len(fake.AskedMessages))
	}
	if fake.AskedMessages[0] != "하나 고르세요" {
		t.Errorf("첫 질문 = %q", fake.AskedMessages[0])
	}
}

func TestPrompterErrorsPropagate(t *testing.T) {
	want := errors.New("사용자가 취소함")
	defer SetPrompter(&FakePrompter{Err: want})()

	if _, err := AskSelect("m", nil); !errors.Is(err, want) {
		t.Errorf("AskSelect 오류 = %v", err)
	}
	if _, err := AskMultiSelect("m", nil); !errors.Is(err, want) {
		t.Errorf("AskMultiSelect 오류 = %v", err)
	}
	if _, err := AskInput("m", 0); !errors.Is(err, want) {
		t.Errorf("AskInput 오류 = %v", err)
	}
}

// SetPrompter 는 이전 구현을 되돌려야 한다.
func TestSetPrompterRestores(t *testing.T) {
	original := prompter
	restore := SetPrompter(&FakePrompter{})
	if prompter == original {
		t.Error("교체되지 않았다")
	}
	restore()
	if prompter != original {
		t.Error("되돌아가지 않았다")
	}
}

// 기본 구현이 surveyPrompter 인지 확인한다.
func TestDefaultPrompterIsSurvey(t *testing.T) {
	if _, ok := prompter.(surveyPrompter); !ok {
		t.Errorf("기본 구현 = %T, 기대 surveyPrompter", prompter)
	}
}

func TestFocusGreen(t *testing.T) {
	icons := &survey.IconSet{}
	focusGreen(icons)
	if icons.SelectFocus.Format != "green+hb" {
		t.Errorf("SelectFocus.Format = %q", icons.SelectFocus.Format)
	}
}
