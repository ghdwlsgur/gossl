package internal

import "github.com/AlecAivazis/survey/v2"

type (
	Domain struct {
		Name string
	}
)

func AskDomain() (*Domain, error) {
	var domainName string

	prompt := &survey.Input{
		Message: "What is your domain ?",
	}

	if err := survey.AskOne(prompt, &domainName, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(20)); err != nil {
		return nil, err
	}

	return &Domain{Name: domainName}, nil
}
