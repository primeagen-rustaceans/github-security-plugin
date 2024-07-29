package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    // "encoding/hex"
    // "fmt"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"

    "github.com/spf13/cobra"
    "golang.org/x/crypto/scrypt"
)

func main() {
    var password string
    var folder string

    var rootCmd = &cobra.Command{
        Use:   "filecrypt",
        Short: "File encryption CLI",
    }

    var encryptCmd = &cobra.Command{
        Use:   "encrypt",
        Short: "Encrypt a folder",
        Run: func(cmd *cobra.Command, args []string) {
            key := deriveKey(password)
            encryptFolder(folder, key)
        },
    }

    var decryptCmd = &cobra.Command{
        Use:   "decrypt",
        Short: "Decrypt a folder",
        Run: func(cmd *cobra.Command, args []string) {
            key := deriveKey(password)
            decryptFolder(folder, key)
        },
    }

    rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Password for encryption/decryption")
    rootCmd.PersistentFlags().StringVarP(&folder, "folder", "f", "", "Folder to encrypt/decrypt")
    rootCmd.MarkPersistentFlagRequired("password")
    rootCmd.MarkPersistentFlagRequired("folder")

    rootCmd.AddCommand(encryptCmd, decryptCmd)
    rootCmd.Execute()
}

func deriveKey(password string) []byte {
    salt := []byte("somesalt")
    key, _ := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
    return key
}

func encryptFolder(folder string, key []byte) {
    filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
        if !info.IsDir() {
            encryptFile(path, key)
        }
        return nil
    })
}

func decryptFolder(folder string, key []byte) {
    filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
        if !info.IsDir() {
            decryptFile(path, key)
        }
        return nil
    })
}

func encryptFile(filename string, key []byte) {
    plaintext, _ := ioutil.ReadFile(filename)
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    ioutil.WriteFile(filename, ciphertext, 0644)
}

func decryptFile(filename string, key []byte) {
    ciphertext, _ := ioutil.ReadFile(filename)
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, _ := gcm.Open(nil, nonce, ciphertext, nil)
    ioutil.WriteFile(filename, plaintext, 0644)
}
