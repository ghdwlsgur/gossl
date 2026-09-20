package internal

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

type (
	Wrapper[T any] struct {
		value *T
	}
	Answer struct {
		Name string
	}

	AnswerList struct {
		Name []string
	}
)

type ReturnType interface {
	Answer | AnswerList
}

func newField[T ReturnType](value T) *Wrapper[T] {
	return &Wrapper[T]{
		value: &value,
	}
}

func getAnswer[T ReturnType](w *Wrapper[T]) *T {
	return w.value
}

// AskMultiSelect 는 여러 개를 고르게 한다.
func AskMultiSelect(message string, options []string) ([]string, error) {
	return prompter.MultiSelect(message, options)
}

// AskInput 은 자유 입력을 받는다.
// pageSize 는 입력 프롬프트에 의미가 없어 무시한다. 호출부 호환을 위해 남겨 둔다.
func AskInput(message string, pageSize int) (string, error) {
	_ = pageSize
	return prompter.Input(message)
}

// AskSelect 는 하나를 고르게 한다.
func AskSelect(message string, options []string) (string, error) {
	return prompter.Select(message, options)
}

func PrintSplitFunc(field, value string) {
	for i, n := range strings.Split(value, ",") {
		if i == 0 {
			PrintFunc(field, n)
		} else {
			fmt.Printf("\t\t%s\n", n)
		}
	}
}

func PrintFunc(field, value string) {
	if len(field) < 8 {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString(field), value)
	} else {
		fmt.Printf("%s\t%s\n", color.HiBlackString(field), value)
	}
}
