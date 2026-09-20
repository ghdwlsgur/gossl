package internal

import "github.com/AlecAivazis/survey/v2"

// Prompter 는 사용자에게 묻는 동작의 경계다.
//
// 예전에는 AskSelect 계열이 survey 를 직접 호출해서 TTY 없이는 실행할 수
// 없었고, 이 함수들을 지나는 모든 코드가 테스트 밖에 놓였다. 경계를 두어
// 테스트에서는 미리 정한 답을 돌려주는 구현으로 바꿔 끼운다.
type Prompter interface {
	Select(message string, options []string) (string, error)
	MultiSelect(message string, options []string) ([]string, error)
	Input(message string) (string, error)
}

// surveyPrompter 는 실제 터미널에 묻는 기본 구현이다.
type surveyPrompter struct{}

func focusGreen(icons *survey.IconSet) {
	icons.SelectFocus.Format = "green+hb"
}

func (surveyPrompter) Select(message string, options []string) (string, error) {
	pageSize := len(options)
	if pageSize > 10 {
		pageSize = 10
	}

	answer := ""
	if err := survey.AskOne(
		&survey.Select{Message: message, Options: options},
		&answer,
		survey.WithIcons(focusGreen),
		survey.WithPageSize(pageSize),
	); err != nil {
		return "", err
	}
	return getAnswer(newField(Answer{Name: answer})).Name, nil
}

func (surveyPrompter) MultiSelect(message string, options []string) ([]string, error) {
	answer := []string{}
	if err := survey.AskOne(
		&survey.MultiSelect{Message: message, Options: options},
		&answer,
		survey.WithIcons(focusGreen),
		survey.WithPageSize(len(options)),
	); err != nil {
		return nil, err
	}
	return getAnswer(newField(AnswerList{Name: answer})).Name, nil
}

func (surveyPrompter) Input(message string) (string, error) {
	answer := ""
	if err := survey.AskOne(
		&survey.Input{Message: message},
		&answer,
		survey.WithIcons(focusGreen),
	); err != nil {
		return "", err
	}
	return getAnswer(newField(Answer{Name: answer})).Name, nil
}

// prompter 는 현재 쓰이는 구현이다. 기본은 터미널이다.
var prompter Prompter = surveyPrompter{}

// SetPrompter 는 구현을 바꿔 끼우고 되돌리는 함수를 돌려준다.
//
//	defer SetPrompter(fake)()
func SetPrompter(p Prompter) func() {
	previous := prompter
	prompter = p
	return func() { prompter = previous }
}
