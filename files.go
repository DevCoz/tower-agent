package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

// Refuse symlinks in every existing ancestor, including dangling links.
func safePath(path string) error {
	for path = filepath.Clean(path); ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			return errors.New("unsupported_host")
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsupported_host")
		}
		if filepath.Dir(path) == path {
			return nil
		}
	}
}
func readFile(path string) ([]byte, error) {
	if err := safePath(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("unsupported_host")
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return nil, errors.New("unsupported_host")
	}
	return data, nil
}
func makeDirectory(path string, mode os.FileMode) error {
	if err := safePath(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := safePath(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tower-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temp, path)
}
func removeFile(path string) error {
	if err := safePath(path); err != nil {
		return err
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
