package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	//golangVersionInfo := runtime.Version()
	//fmt.Println("ver")
	logger, cmd, cipher := generateLoggerCmdCipher()
	cmd.exportPublicKeyToCertificateFile(cipher)
	cmd.writePrivateKeyToFile(cipher)
	closeLogger(logger)
}

func generateLoggerCmdCipher() (*log.Logger, *Cmd, Cipher) {
	logger, cmd := readFromCmdInputs()
	logger.Println(cmd)
	cipher := cmd.generateCipher()
	return logger, cmd, cipher
}

func closeLogger(logger *log.Logger) {
	logger.Println("\n...........END...............")
}

func readFromCmdInputs() (*log.Logger, *Cmd) {
	logger := createLogger()
	cmd := &Cmd{}
	cmd.setFlagParametersForCmd()
	flag.Parse()
	return logger, cmd
}

func createLogger() *log.Logger {
	loggerFile, err := os.OpenFile("text.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	logger := log.New(loggerFile, "Keygen|", log.LstdFlags)
	logger.Println("\n\n\n------------------------Log File Created----------------------")
	return logger
}
