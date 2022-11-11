package internal

import "github.com/AlecAivazis/survey/v2"

type (
	Domain struct {
		Name string
	}

	ReqDomain struct {
		Name string
	}
)

func AskCertFile(FileList []string) (string, error) {
	prompt := &survey.Select{
		Message: "choose file",
		Options: FileList,
	}

	answer := ""
	if err := survey.AskOne(prompt, &answer, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(20)); err != nil {
		return "", err
	}

	return answer, nil
}

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

func AskReqDomain() (*ReqDomain, error) {
	var reqDomainName string

	prompt := &survey.Input{
		Message: "What is your request domain ?",
	}

	if err := survey.AskOne(prompt, &reqDomainName, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(2)); err != nil {
		return nil, err
	}

	return &ReqDomain{Name: reqDomainName}, nil

}
