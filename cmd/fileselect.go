package cmd

import (
	"fmt"
	"os"

	"github.com/ghdwlsgur/gossl/internal"
)

// resolveCertFile 은 대상 파일을 정한다.
//
// name 이 비어 있지 않으면 그 파일을 그대로 쓰고 프롬프트를 띄우지 않는다.
// 비어 있으면 현재 디렉토리를 훑어 고르게 한다. 파이프라인에서는 인자를
// 주고, 손으로 쓸 때는 생략하면 된다.
func resolveCertFile(prompt, name string) (*internal.CertFile, string, error) {
	if name != "" {
		if err := statCertFile(name); err != nil {
			return nil, "", err
		}
		c := &internal.CertFile{Name: []string{name}}
		internal.SetCertExtension(c, name)
		return c, name, nil
	}

	c, err := internal.DirGrepX509()
	if err != nil {
		return nil, "", err
	}
	selected, err := internal.AskSelect(prompt, c.Name)
	if err != nil {
		return nil, "", err
	}
	internal.SetCertExtension(c, selected)
	return c, selected, nil
}

// statCertFile 은 인자로 받은 경로가 읽을 수 있는 파일인지 본다.
// 디렉토리를 건네면 읽기 단계에서 알아보기 어려운 오류가 나므로 먼저 막는다.
func statCertFile(name string) error {
	info, err := os.Stat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a certificate file", name)
	}
	return nil
}

// stdinIsTerminal 은 프롬프트를 띄울 수 있는 상태인지 본다.
// 거짓이면 물어보는 대신 실패해야 한다. CI 에서 멈춰 있는 것보다 낫다.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
