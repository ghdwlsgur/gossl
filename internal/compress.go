package internal

import (
	"archive/zip"
	"io"
	"os"
)

func AppendFile(fileName string, zipw *zip.Writer) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	wr, err := zipw.Create(fileName)
	if err != nil {
		return err
	}

	if _, err := io.Copy(wr, file); err != nil {
		return err
	}

	return nil
}
