package main

import (
    "flag"
    "os"
    "encoding/json"
    "fmt"
    "io/ioutil"
)

type Locker struct {
    Cmd
    directoryPath string
    keyFilePath string
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

func (locker *Locker) generateCipher(name string) Cipher {
    var cipher Cipher
    if name == "ec" {
        locker.AlgorithmType = "ec"
        cipher = locker.generateECCipher(cipher)
    } else if name == "rsa"  {
        locker.AlgorithmType = "rsa"
        cipher = locker.generateRSACipher(cipher)
    } else {
        panic("Algorithm Not Specified! You can ONLY pick ec or RSA.")
    }
    return cipher
}


