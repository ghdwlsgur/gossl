package internal

import (
	"fmt"
	"os"
	"strings"
)

type CertFile struct {
	Name      []string
	Extension string
}

func (c CertFile) getExtension() string {
	return c.Extension
}

func (c CertFile) getCertFileLength() int {
	return len(c.Name)
}

func Dir() (*CertFile, error) {

	fileInfo, err := os.ReadDir("./")
	if err != nil {
		return nil, err
	}

	c := &CertFile{}
	for _, f := range fileInfo {
		if !f.Type().IsDir() {
			s := strings.Split(f.Name(), ".")
			extension := s[len(s)-1]
			if extension == "pem" || extension == "crt" || extension == "key" {
				c.Name = append(c.Name, f.Name())
			}
		}
	}

	if c.getCertFileLength() == 0 {
		return nil, fmt.Errorf("there are no extension files(pem, crt, key) in the current directory")
	}

	return c, nil
}

func GetCertExtension(c *CertFile) string {
	return c.getExtension()
}

func SetCertExtension(c *CertFile, file string) {
	wordList := strings.Split(file, ".")
	c.Extension = strings.Split(file, ".")[len(wordList)-1]
}
