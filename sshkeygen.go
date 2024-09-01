package main

import (
	"os"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

func generateSSHKeyPair(publicKeyPath, privateKeyPath string) error {
	// Check if Key exists
	_, err := os.Stat(privateKeyPath)

	// No error means the key exists, do nothing
	if err == nil {
		return nil
	}

	// If error isn't "doesn't exist" exit
	if !os.IsNotExist(err) {
		return err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	privateKeyFile, err := os.Create(privateKeyPath)
	defer privateKeyFile.Close()
	if err != nil {
		return err
	}

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	if err := os.Chmod(privateKeyPath, 0600); err != nil {
		return err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(pub), 0644)
}
