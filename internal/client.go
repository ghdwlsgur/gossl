package internal

import (
	"github.com/AlecAivazis/survey/v2"
)

/*
=======================

	&Wrapper[Answer]{
		value: &Answer{
			Name: answer,
		},
	}

=======================
*/
type (
	Wrapper[T any] struct {
		value *T
	}
	Answer struct {
		Name string
	}
)

type ReturnType interface {
	Answer
}

func newField[T ReturnType](value T) *Wrapper[T] {
	return &Wrapper[T]{
		value: &value,
	}
}

func getAnswer[T ReturnType](w *Wrapper[T]) *T {
	return w.value
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

func AskSelect(Message string, FileList []string, PageSize int) (string, error) {

	prompt := &survey.Select{
		Message: Message,
		Options: FileList,
	}

	answer := ""
	if err := survey.AskOne(prompt, &answer, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(PageSize)); err != nil {
		return "", err
	}

	return answer, nil
}
