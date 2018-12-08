package main

import (
    "flag"
    "os"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "crypto/rand"
	"strings"
	"crypto/aes"
	"io"
	"crypto/cipher"
	"log"
	"math/big"
)

type Unlocker struct {
    Cmd
    directoryPath string
    keyFilePath string
    pubkey string
    privkey string
}

func (unlocker *Unlocker) fetchJsonMap(path string ) map[string]interface{} {
    jsonFile, err := os.Open(path)
    // if we os.Open returns an error then handle it
    if err != nil {
        fmt.Println(err)
    }
    fmt.Println("Successfully Opened users.json")
    // defer the closing of our jsonFile so that we can parse it later on
    defer jsonFile.Close()

    byteValue, _ := ioutil.ReadAll(jsonFile)

    var result map[string]interface{}
    json.Unmarshal([]byte(byteValue), &result)
    return result
}

func (unlocker *Unlocker) getPubKeyJSONMap() map[string]interface{} {
    result := unlocker.fetchJsonMap(unlocker.publicKeyFilePath)
    return result
}


func (unlocker *Unlocker) setFlagParameters() {
    flag.StringVar(&unlocker.directoryPath, "d", "", "Directory to lock")
    flag.StringVar(&unlocker.publicKeyFilePath, "p", "", "Public Key File Path")
    flag.StringVar(&unlocker.privateKeyFilePath, "r", "", "Private Key File Path")
    flag.StringVar(&unlocker.Subject, "s", "", "Subject Name")
}
//
//- - - - - - - - - - - - - - - - - - - - - - - - - - - - -- - - - - - - - - - - - - - - - - - read keyfile.sig and verify signature, return boolean
//
func (unlocker *Unlocker) readSigAndValidate(directoryPath, pubKeyfilePath string) bool {
	//
	// - - - - - create keyfile path
	//
	keyfilePath := unlocker.getKeyfilePath()
	//
	// - - - - - create keyfile.sig path
	//
	keyfileSigPath := unlocker.getKeySigfilePath()
	//
	// - - - - - read signature and verify
	//
	signature, _ := ioutil.ReadFile(keyfileSigPath)
	ele := strings.Split(string(signature), ";")
	r := new(big.Int)
	s := new(big.Int)
	_, _ = r.SetString(ele[0], 10)
	_, _ = s.SetString(ele[1], 10)
	var ec_fromPub ECCipher
	ec_fromPub.getPublicKeyFromFile(pubKeyfilePath)
	message, _ := ioutil.ReadFile(keyfilePath)
	return ec_fromPub.VerifySignature(message, r, s)
}
//
//- - - - - - - - - - - - - - - - - - - - - - - - - - - - -- - - - - - - - - - - - -import encrypted AES key to keyfile in directory.
//
func (unlocker *Unlocker) importEncryptedAES() []byte {
	//
	// - - - - - create keyfile path
	//
	var aeskey []byte
	keyfilePath := unlocker.getKeyfilePath()
	//
	//- - - - - - read and decrypt
	//
	aeskeyCipherText,_ := ioutil.ReadFile(keyfilePath)
	aeskey = unlocker.decryptAESkey(aeskeyCipherText,unlocker.privateKeyFilePath)
	return aeskey
}
//
//- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -decrypt aeskey using private key file, returns aeskey plaintext
//
func (unlocker *Unlocker) decryptAESkey(aeskeyciphertext []byte, privKeyfilePath string) []byte {
	var rsaFromPriv RSACipher
	rsaFromPriv.getPrivateKeyFromFile(privKeyfilePath)
	return rsaFromPriv.Decrypt(aeskeyciphertext)
}
//
// - - - - - - - - - - - -  - - - - - - - - - - return keyfile path string
//
func (unlocker *Unlocker) getKeyfilePath() string {
	var dirPath string
	dirPath = unlocker.directoryPath
	//
	// - - - - - - append keyfile to path
	//
	tempDirPath := strings.Split(dirPath,"/")
	tempDirPath = append(tempDirPath,"keyfile")
	dirPath = strings.Join(tempDirPath,"/")

	return dirPath
}
//
// - - - - - - - - - - - -  - - - - - - - - - - - - - return keyfile.sig path string
//
func (unlocker *Unlocker) getKeySigfilePath() string {
	var dirPath string
	dirPath = unlocker.directoryPath
	//
	// - - - - - - append keyfile.sig to path
	//
	tempDirPath := strings.Split(dirPath,"/")
	tempDirPath = append(tempDirPath,"keyfile.sig")
	dirPath = strings.Join(tempDirPath,"/")

	return dirPath
}
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -DECRYPT FILE AND REPLACE
//
func (unlocker *Unlocker) decryptFileAndReplace(filename string,aesKey []byte) {
	//
	// - - - read plaintext into memory buffer
	//
	file,_ := os.Open(filename)
	ciphertext,_ := ioutil.ReadAll(file)
	//
	// - - - -DELETE FILE
	//
	file.Close()
	err := os.Remove(filename)
	if err != nil {
		log.Fatal(err)
	}
	//
	// - - - CREATE STRONG PSF
	//
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err.Error())
	}
	//
	// - - -  Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	//
	nonce :=  ciphertext[64:(64+24)]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	//
	//- - - - CREATE BLOCK CIPHER
	//
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	//
	// - - - -DECRYPT
	//
	plaintext,_ := aesgcm.Open(nil, nonce, ciphertext, aesKey)
	//
	// CREATE NEW FILE
	//
	//
	//- - - - - - - write aes plaintext to file
	//
	outFile, _ := os.Create(filename)
	defer outFile.Close()
	_, _ = outFile.Write(plaintext)
	_ = outFile.Sync()
	outFile.Close()
}


