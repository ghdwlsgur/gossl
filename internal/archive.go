package internal

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

type CertFile struct {
	Name      []string
	Extension string
}

type ZipFile struct {
	Name []string
}

type ExtensionX509 struct {
	typeA string
	typeB string
	typeC string
	typeD string
	typeE string
}

type ExtensionZip struct {
	name string
}

func (c CertFile) getExtension() string {
	return c.Extension
}

func (c CertFile) getCertFileLength() int {
	return len(c.Name)
}

func (z ZipFile) getZipFileLength() int {
	return len(z.Name)
}

func GetCertExtension(c *CertFile) string {
	return c.getExtension()
}

func SetCertExtension(c *CertFile, file string) {
	wordList := strings.Split(file, ".")
	c.Extension = strings.Split(file, ".")[len(wordList)-1]
}

func DirGrepZip() (*ZipFile, error) {

	fileInfo, err := os.ReadDir("./")
	if err != nil {
		return nil, err
	}

	z := &ZipFile{}
	for _, f := range fileInfo {
		if !f.Type().IsDir() {
			s := strings.Split(f.Name(), ".")
			extension := s[len(s)-1]

			e := &ExtensionZip{
				name: "zip",
			}

			if extension == e.name {
				z.Name = append(z.Name, f.Name())
			}
		}
	}

	if z.getZipFileLength() == 0 {
		return nil, fmt.Errorf("[zip] extension files do not exist")
	}
	return z, nil
}

func DirGrepX509() (*CertFile, error) {

	fileInfo, err := os.ReadDir("./")
	if err != nil {
		return nil, err
	}

	c := &CertFile{}
	for _, f := range fileInfo {
		if !f.Type().IsDir() {
			s := strings.Split(f.Name(), ".")
			extension := s[len(s)-1]

			e := &ExtensionX509{
				typeA: "pem",
				typeB: "crt",
				typeC: "key",
				typeD: "ca",
				typeE: "csr",
			}

			if extension == e.typeA ||
				extension == e.typeB ||
				extension == e.typeC ||
				extension == e.typeD ||
				extension == e.typeE {
				c.Name = append(c.Name, f.Name())
			}
		}
	}

	if c.getCertFileLength() == 0 {
		return nil, fmt.Errorf("[pem, crt, key, ca, csr] extension files do not exist")
	}

	return c, nil
}

func UnZip(targetDirectory, newFileName string) error {

	dst := newFileName
	archive, err := zip.OpenReader(targetDirectory)
	if err != nil {
		return err
	}
	defer archive.Close()

	fi, err := os.Stat(targetDirectory)
	if err != nil {
		return err
	}
	if fi.Size() <= 22 {
		return fmt.Errorf("%s is empty", targetDirectory)
	}

	for _, f := range archive.File {

		fPath := filepath.Join(dst, f.Name)

		if f.FileInfo().IsDir() {
			fmt.Printf("%s\t%s\n", color.HiGreenString("📁 creating directory"), fPath)
			os.MkdirAll(fPath, os.ModePerm)
			continue
		}
		fmt.Printf("%s\t%s\n", color.HiGreenString("📄 unzipping file"), fPath)

		if !strings.HasPrefix(fPath, filepath.Clean(dst)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path")
		}

		if err := os.MkdirAll(filepath.Dir(fPath), os.ModePerm); err != nil {
			return err
		}

		dstFile, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return err
		}

		dstFile.Close()
		fileInArchive.Close()
	}
	return nil
}
