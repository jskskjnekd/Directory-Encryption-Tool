package main

import (
	"flag"
	"log"
	"os"
)

type Cmd struct {
	AlgorithmType      string
	Subject            string
	publicKeyFilePath  string
	privateKeyFilePath string
}

func main() {
	logger := createLogger()
	cmd := &Cmd{}
	setFlagParametersForCmd(cmd)
	flag.Parse()
	logger.Println(cmd)
	logger.Println("..........................")
}

func setFlagParametersForCmd(cmd *Cmd) {
	flag.StringVar(&cmd.AlgorithmType, "t", "", "Algorithm Type: rsa or ec")
	flag.StringVar(&cmd.Subject, "s", "", "Subject Name")
	flag.StringVar(&cmd.publicKeyFilePath, "pub", "", "Public Key File Path")
	flag.StringVar(&cmd.privateKeyFilePath, "priv", "", "Private Key File Path")
}

func createLogger() *log.Logger {
	f, err := os.OpenFile("text.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	logger := log.New(f, "Keygen|", log.LstdFlags)
	logger.Println("\n\n\n------------------------Log File Created----------------------")
	return logger
}
