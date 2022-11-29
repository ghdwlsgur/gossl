package internal

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
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

func AskMultiSelect(Message string, Options []string) ([]string, error) {

	prompt := &survey.MultiSelect{
		Message: Message,
		Options: Options,
	}

	answer := []string{}
	if err := survey.AskOne(prompt, &answer, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(len(Options))); err != nil {
		return nil, nil
	}

	n := newField(AnswerList{
		Name: answer,
	})

	return getAnswer(n).Name, nil
}

func AskInput(Message string, PageSize int) (string, error) {

	prompt := &survey.Input{
		Message: Message,
	}

	answer := ""
	if err := survey.AskOne(prompt, &answer, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(PageSize)); err != nil {
		return "", err
	}

	n := newField(Answer{
		Name: answer,
	})

	return getAnswer(n).Name, nil
}

func AskSelect(Message string, Options []string) (string, error) {

	prompt := &survey.Select{
		Message: Message,
		Options: Options,
	}

	answer := ""
	if err := survey.AskOne(prompt, &answer, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(len(Options))); err != nil {
		return "", err
	}

	n := newField(Answer{
		Name: answer,
	})

	return getAnswer(n).Name, nil
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
