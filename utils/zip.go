package utils

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

func Unzip(zipFile string, destDir string) error {
	zipReader, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer zipReader.Close()
	for _, f := range zipReader.File {
		fpath := filepath.Join(destDir, f.Name)
		if f.FileInfo().IsDir() {
			err := os.MkdirAll(fpath, 0o700)
			if err != nil {
				return err
			}
		} else {
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				return err
			}

			inFile, err := f.Open()
			if err != nil {
				return err
			}

			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				inFile.Close()
				return err
			}
			_, err = io.Copy(outFile, inFile)
			inFile.Close()
			outFile.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func UnzipAllInDir(dir string, dest string) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return xerrors.Errorf("file walk error: %w", err)
		}
		if !strings.HasSuffix(path, ".zip") {
			return nil
		}
		err = Unzip(path, "./vuln-list/cnnvd")
		if err != nil {
			return xerrors.Errorf("error in unzip file : %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in walk: %w", err)
	}
	return nil
}
