package internal

import (
	"os"
	"strings"
)

type CertFile struct {
	Name []string
}

func Dir() (*CertFile, error) {

	fileInfo, err := os.ReadDir("./")
	if err != nil {
		return nil, err
	}

	certFile := &CertFile{}
	for _, f := range fileInfo {
		if !f.Type().IsDir() {
			s := strings.Split(f.Name(), ".")
			extension := s[len(s)-1]
			if extension == "pem" || extension == "crt" || extension == "key" {
				certFile.Name = append(certFile.Name, f.Name())
			}
		}
	}

	return certFile, nil
}
