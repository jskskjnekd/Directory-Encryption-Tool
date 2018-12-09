package main

import (
    "flag"
    "os"
    "io/ioutil"
    "path/filepath"
    "log"
    "encoding/json"
    "strings"
)

type Cmd struct {
    AlgorithmType      string
    Subject            string
    publicKeyFilePath  string
    privateKeyFilePath string
}

func (cmd *Cmd) writePrivateKeyToFile(cipher Cipher) {
    fullPrivateKey := cipher.getPublicKeyAlgorithm() + ";" + cipher.getPrivateKeyData()
    f, _ := os.Create(cmd.privateKeyFilePath)
    _, _ = f.Write([]byte(fullPrivateKey))
}

func (cmd *Cmd) exportPublicKeyToCertificateFile(cipher Cipher) {
    var cert certificate
    cert.generate(cipher, cmd.Subject)
    cert.exportJson()
    cert.exportJsonToFile(cmd.publicKeyFilePath)
}

func (cmd *Cmd) generateRSACipher(cipher Cipher) Cipher {
    var rsa RSACipher
    rsa.generate()
    cipher = &rsa
    return cipher
}

func (cmd *Cmd) generateECCipher(cipher Cipher) Cipher {
    var ec ECCipher
    ec.generate()
    cipher = &ec
    return cipher
}

func (cmd *Cmd) generateCipher() Cipher {
    var cipher Cipher
    if cmd.AlgorithmType == "ec" {
        cipher = cmd.generateECCipher(cipher)
    } else if cmd.AlgorithmType == "rsa" {
        cipher = cmd.generateRSACipher(cipher)
    } else {
        panic("Algorithm Not Specified! You can ONLY pick ec or RSA.")
    }
    return cipher
}
func (cmd *Cmd) setFlagParametersForCmd() {
    flag.StringVar(&cmd.AlgorithmType, "t", "", "Algorithm Type: rsa or ec")
    flag.StringVar(&cmd.Subject, "s", "", "Subject Name")
    flag.StringVar(&cmd.publicKeyFilePath, "pub", "", "Public Key File Path")
    flag.StringVar(&cmd.privateKeyFilePath, "priv", "", "Private Key File Path")
}
//
// - - - - - - - - - returns ciphers
//
/*func (cmd *Cmd) extractCipherPriv() Cipher {
    var cipher Cipher
    cipher = cmd.extractCipher(cmd.privateKeyFilePath)
    return cipher
}
//
func (cmd *Cmd) extractCipherPub() Cipher {
    var cipher Cipher
    cipher = cmd.extractCipher(cmd.publicKeyFilePath)
    return cipher
}*/
//
// - - - - - - - - returns cipher based on path
//
/*func (cmd *Cmd) extractCipher(keyPath string) Cipher {
    //
    //
    //
    var cipher Cipher
    var certFromJsonFile certificate
    //
    jsonFile, _ := os.Open(keyPath)
    jsonContent, _ := ioutil.ReadAll(jsonFile)
    _ = json.Unmarshal(jsonContent, &certFromJsonFile)
    //
    //
    //
    algoType := certFromJsonFile.PublicKeyAlgorithm
    switch {

    case algoType == "ECC P256":
        //
        cipher = cmd.generateECCipher(cipher)
        cipher.getPrivateKeyFromFile(keyPath)
        return cipher
        //
    case algoType == "RSA Encryption":
        //
        cipher = cmd.generateRSACipher(cipher)
        cipher.getPrivateKeyFromFile(keyPath)
        return cipher
        //
    default:
        panic("algorithm type not correct")
    }
}*/
func (cmd *Cmd) extractJsonfile(filename string) certificate {
    //
    // - - - - - - - parse the certificate
    //
    var certFromJsonFile certificate
    jsonFile, _ := os.Open(filename)
    jsonContent, _ := ioutil.ReadAll(jsonFile)
    _ = json.Unmarshal(jsonContent, &certFromJsonFile)
    //
    //
    //
    return certFromJsonFile
}
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -VALIDATION STEP 1
//
func (cmd *Cmd) validatePubKeyFileSubject(filename string) bool{
    //
    //
    //
    var certFromJsonFile certificate
    certFromJsonFile = cmd.extractJsonfile(filename)
    //
    //
    //
    var validation bool
    validation = certFromJsonFile.Subject == cmd.Subject
    return validation
}
//
// - - - - - - - - - - - - RECURSIVELY WALK FILES STARTING AT ROOT
//
func (cmd *Cmd) fileWalkRecursive(searchDir string) []string {
    fileList := []string{}
    filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
        if strings.Contains(path,"keyfile") || f.IsDir() {
            return nil
        }

        fileList = append(fileList, path)
        return nil
    })
    return fileList

}
//
// - - - - - - - - - - - - WRITE BYTES
//
func (cmd *Cmd) writeBytes(filename string, bytes []byte) {
    file, err := os.OpenFile(
        filename,
        os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
        0666,
    )
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    // Write bytes to file
    file.Write(bytes)
    if err != nil {
        log.Fatal(err)
    }


}
//
// - - - - - - - - - - - -GET FILE BYTES
//
func (cmd *Cmd) getFileBytes(filepath string) []byte {
    file, err := os.Open(filepath)
    if fi, _ := file.Stat(); err != nil || fi.IsDir() {
        // error or is directory
        panic("directory path is invalid, or not a directory")
    }
    fileContent, _ := ioutil.ReadAll(file)
    return fileContent
}

