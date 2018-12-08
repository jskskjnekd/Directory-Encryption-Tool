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
	N,e := locker.sign(locker.getKeyfilePath())
	locker.writeSigString(N,e)
}
//
//- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - SIGN the keyfile uses private key
//
func (locker *Locker) sign(filepath string) (r string, s string) {
	//
	// - - - - - -extract cipher with private signature
	//
	var cipher ECCipher
	cipher.getPrivateKeyFromFile(locker.privateKeyFilePath)
	//
	// - - - - - -get file contents and sign, returning signature
	//
	fileContents := locker.getFileBytes(filepath)
	pR,pS := cipher.Sign(fileContents)

	return pR.String(),pS.String()
}
//
//- - - - - - - - - - - - - - - - - - convert string sig to bytes and write to keyfile.sig (ASSUMES keyfile.sig EXISTS ALREADY)
//
func (locker *Locker) writeSigString( r string, s string) {

	var sigFilePath string
	tempSigFile := strings.Split(locker.directoryPath,"/")
	tempSigFile = append(tempSigFile,"keyfile.sig")
	sigFilePath = strings.Join(tempSigFile,"/")
	output := r +";"+s
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
	// - - - CREATE STRONG PSF
	//
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err.Error())
	}
	//
	// - - -  Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	//
	nonce := make([]byte, 12)
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
	// - - - -ENCRYPT
	//
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
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


