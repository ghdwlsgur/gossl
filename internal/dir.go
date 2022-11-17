package internal

import (
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

	return c, nil
}

func GetCertExtension(c *CertFile) string {
	return c.getExtension()
}

func SetCertExtension(c *CertFile, file string) {
	wordList := strings.Split(file, ".")
	c.Extension = strings.Split(file, ".")[len(wordList)-1]
}
