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

type Locker struct {
    Cmd
    directoryPath string
    keyFilePath string
    pubkey string
    privkey string
}



func (locker *Locker) fetchJsonMap(path string ) map[string]interface{} {
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

func (locker *Locker) getPubKeyJSONMap() map[string]interface{} {
    result := locker.fetchJsonMap(locker.publicKeyFilePath)
    return result
}


func (locker *Locker) setFlagParameters() {
    flag.StringVar(&locker.directoryPath, "d", "", "Directory to lock")
    flag.StringVar(&locker.publicKeyFilePath, "p", "", "Public Key File Path")
    flag.StringVar(&locker.privateKeyFilePath, "r", "", "Private Key File Path")
    flag.StringVar(&locker.Subject, "s", "", "Subject Name")
}
//
//
//
//
// - - - - - - - - - - - - - - - - - - - - - - - - -- - - - GENERATE AES KEY
//
func (locker *Locker) generateAESKey(length int) []byte {

    AESkey := make([]byte, length)
    _, _ = rand.Read(AESkey)
    return AESkey
}
//
// - - - - - - - - - - - - - - - - - - - - - -- - - - - - -ENCRYPT AES KEY
//
func (locker *Locker) encryptedAES(aeskey []byte) []byte {
    //
    //- - - - - - -using locker.publickey. encrypt AES
    //
    var aesKeyCipherText []byte
    var cipher RSACipher
	//
	//- - - - - - - read public key from file, and use to encrypt aeskey
	//
	cipher.getPublicKeyFromFile(locker.publicKeyFilePath)
	aesKeyCipherText = cipher.Encrypt(aeskey)
	//
	//
	//
	return aesKeyCipherText
}
//
// - - - - - - - - - - - - - - - - - - - - - -- - - - - - -export encrypted AES key to keyfile in directory.
//
func (locker *Locker) exportEncryptedAES(aeskeyCiphertext []byte) {
	//
	// - - - - - - - - -  - - - - open keyfile
	//
	keyFilePath := locker.getKeyfilePath()
	locker.writeBytes(keyFilePath,aeskeyCiphertext)
}
//
// - - - - - - - - - - - -  - - - - -- - - - - return keyfile path string
//
func (locker *Locker) getKeyfilePath() string {
	var dirPath string
	dirPath = locker.directoryPath
	//
	// - - - - - - append keyfile to path
	//
	tempDirPath := strings.Split(dirPath,"/")
	tempDirPath = append(tempDirPath,"keyfile")
	dirPath = strings.Join(tempDirPath,"/")

	return dirPath
}
//
// - - - - - - - - - - - -  - - - - - - - - - - return keyfile.sig path string
//
func (locker *Locker) getKeySigfilePath() string {
	var dirPath string
	dirPath = locker.directoryPath
	//
	// - - - - - - append keyfile.sig to path
	//
	tempDirPath := strings.Split(dirPath,"/")
	tempDirPath = append(tempDirPath,"keyfile.sig")
	dirPath = strings.Join(tempDirPath,"/")

	return dirPath
}
//
// - - - - - - - - - - - -  - - - - - - - - - - - keyfile.sig
//
func (locker *Locker) exportKeyfileSignature() {
	//
	// - - - - - - - sign keyfile
	//
	r,s := locker.sign(locker.getKeyfilePath())
	locker.writeSigString(r,s)
}
//
//- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - SIGN the keyfile uses private key
//
func (locker *Locker) sign(filepath string) (r , s *big.Int) {
	//
	// - - - - - -extract cipher with private signature
	//
	var cipher ECCipher
	cipher.getPrivateKeyFromFile(locker.privateKeyFilePath)
	//
	// - - - - - -get file contents and sign, returning signature
	//
	fileContents := locker.getFileBytes(filepath)
	R,S := cipher.Sign(fileContents)


	return R,S
}
//
//- - - - - - - - - - - - - - - - - - convert string sig to bytes and write to keyfile.sig (ASSUMES keyfile.sig EXISTS ALREADY)
//
func (locker *Locker) writeSigString( r, s *big.Int) {

	var sigFilePath string
	tempSigFile := strings.Split(locker.directoryPath,"/")
	tempSigFile = append(tempSigFile,"keyfile.sig")
	sigFilePath = strings.Join(tempSigFile,"/")
	//
	output := r.String()+";"+s.String()
	//
	var signature []byte
	signature = []byte(output)
	locker.writeBytes(sigFilePath,signature)

}
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -- -ENCRYPT FILE AND REPLACE
//
func (locker *Locker) encryptFileAndReplace(filename string,aesKey []byte) {
	//
	//
	//
	if !strings.Contains(filename,"keyfile") || !strings.Contains(filename,"keyfile.sig") {
	//
	// - - - read plaintext into memory buffer
	//
	file,_ := os.Open(filename)
	plaintext,_ := ioutil.ReadAll(file)
	//
	// - - - -DELETE FILE
	//
	file.Close()
	err := os.Remove(filename)
	if err != nil {
		log.Fatal(err)
	}
	//
	// - - - ENCRYPT
	//
	block, _ := aes.NewCipher(aesKey)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	//fmt.Print(string(ciphertext))
	//
	// CREATE NEW FILE
	//
	//
	//- - - - - - - write aes ciphertext to file
	//
	outFile, _ := os.Create(filename)
	defer outFile.Close()
	_, _ = outFile.Write(ciphertext)
	_ = outFile.Sync()
	outFile.Close()
	}
}


