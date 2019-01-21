package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	aws_credentials "github.com/aws/aws-sdk-go/aws/credentials"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	aws_kms "github.com/aws/aws-sdk-go/service/kms"
)

type myProvider struct {
	v aws_credentials.Value
}

func (mp *myProvider) Retrieve() (aws_credentials.Value, error) {
	return mp.v, nil
}

func (mp *myProvider) IsExpired() bool {
	return false
}

func main() {
	appKey, ok := os.LookupEnv("AWS_ACCESS_KEY")
	if !ok {
		fmt.Printf("can't find AWS_ACCESS_KEY")
		os.Exit(1)
	}
	appSecret, ok := os.LookupEnv("AWS_SECRET")
	if !ok {
		fmt.Printf("can't find AWS_SECRET")
		os.Exit(1)
	}
	region, ok := os.LookupEnv("AWS_REGION")
	if !ok {
		fmt.Printf("can't find AWS_REGION")
		os.Exit(1)
	}
	dataKey, ok := os.LookupEnv("AWS_DATA_KEY")
	if !ok {
		fmt.Printf("can't find data key")
		os.Exit(1)
	}
	binaryDataKey, err := base64.StdEncoding.DecodeString(dataKey)
	if err != nil {
		fmt.Printf("fail to decode data key: %s\n", err)
		os.Exit(1)
	}

	s, err := aws_session.NewSession(&aws.Config{
		Region: &region,
		Credentials: aws_credentials.NewCredentials(&myProvider{
			v: aws_credentials.Value{
				AccessKeyID:     appKey,
				SecretAccessKey: appSecret,
			},
		}),
	})
	if err != nil {
		fmt.Printf("fail to new aws session: %s\n", err)
		os.Exit(1)
	}

	kms := aws_kms.New(s)
	do, err := kms.Decrypt(&aws_kms.DecryptInput{
		CiphertextBlob: binaryDataKey,
	})

	block, err := aes.NewCipher(do.Plaintext)
	if err != nil {
		fmt.Printf("fail to new cipher: %s\n", err)
		os.Exit(1)
	}

	plaintext := []byte("this is plain text")

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// CTR mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])

	fmt.Printf("%s\n", plaintext2)

}
