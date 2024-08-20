package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func TmpCopyDir(src string) (string, error) {
  // Create copy of the directory in the OS temporary directory with the current timestamp
  timenow := time.Now().UTC().Format(time.RFC3339)
  dirName := filepath.Base(src)
  tmpDirPath := fmt.Sprintf("%s/%s-%s",os.TempDir(), dirName, timenow)

  if err := copyDir(src, tmpDirPath); err != nil {
    return "", err
  }

  return tmpDirPath, nil
}

func copyDir(src string, dest string) error {
    // Get properties of source dir
    srcInfo, err := os.Stat(src)
    if err != nil {
        return err
    }

    // Create the destination directory
    err = os.MkdirAll(dest, srcInfo.Mode())
    if err != nil {
        return err
    }

    // Get the list of files in the source directory
    entries, err := os.ReadDir(src)
    if err != nil {
        return err
    }

    // Iterate over each file or directory
    for _, entry := range entries {
        srcPath := filepath.Join(src, entry.Name())
        destPath := filepath.Join(dest, entry.Name())

        if entry.IsDir() {
            // Recursively copy sub-directories
            err = copyDir(srcPath, destPath)
            if err != nil {
                return err
            }
        } else {
            // Copy files
            err = copyFile(srcPath, destPath)
            if err != nil {
                return err
            }
        }
    }

    return nil
}

func copyFile(src, dest string) error {
    // Open the source file
    srcFile, err := os.Open(src)
    if err != nil {
        return err
    }
    defer srcFile.Close()

    // Create the destination file
    destFile, err := os.Create(dest)
    if err != nil {
        return err
    }
    defer destFile.Close()

    // Copy the file contents from src to dest
    _, err = io.Copy(destFile, srcFile)
    if err != nil {
        return err
    }

    // Copy the file mode (permissions)
    srcInfo, err := os.Stat(src)
    if err != nil {
        return err
    }
    return os.Chmod(dest, srcInfo.Mode())
}
