package main

import (
	"fmt"
	"os"
	"text/template"
)

type AnsibleConfiguration struct {
	Linux   string
	Windows string
}

func GenerateConfiguration(conf AnsibleConfiguration) (string, error) {
	t := template.Must(template.ParseFiles("./tmpl/inv.tmpl"))
	dir, err := TmpCopyDir("./ansible")
	invPath := fmt.Sprintf("%s/inventory.yml", dir)

	invFile, err := os.Create(invPath)
	defer invFile.Close()
	if err != nil {
		fmt.Printf("failed to create %s: %v", invPath, err)
		os.Exit(1)
	}

	if err := t.Execute(invFile, conf); err != nil {
		fmt.Printf("failed to execute template %s: %v", t.Name(), err)
		os.Exit(1)
	}

	return dir, nil
}
