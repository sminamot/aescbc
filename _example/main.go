package main

import (
	"fmt"
	"log"

	"github.com/sminamot/aescbc"
)

func main() {
	key := []byte("a1c05c11a49985dd216157277e30597c")
	iv := []byte("test-iv-12345678")

	encrypted, err := aescbc.Encrypt("hogehoge", key, iv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(encrypted)

	decrypted, err := aescbc.Decrypt(encrypted, key, iv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(decrypted)
}
