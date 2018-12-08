rm -rf testData
rm -rf testDirectory

mkdir testData
mkdir testData/lockingParty
mkdir testDAta/unlockingParty

mkdir -p testDirectory/{A,B}/{{A1,A2},{B1,B2}} 
find testDirectory -type d -exec touch {}/TESTFILE \;
find testDirectory -type d -exec echo please encrypt me > TESTFILE \;


./keygen -t ec -s ATypicalSubjectName -pub testData/lockingParty/wECpub -priv testData/lockingParty/wECpriv
./keygen -t rsa -s ATypicalSubjectName -pub testData/lockingParty/wRSApub -priv testData/lockingParty/wRSApriv
./keygen -t ec -s ATypicalSubjectName -pub testData/unlockingParty/wECpub -priv testData/unlockingParty/wECpriv
./keygen -t rsa -s ATypicalSubjectName -pub testData/unlockingParty/wRSApub -priv testData/unlockingParty/wRSApriv
go build lock.go locker.go RSACipher.go cmd.go ECCipher.go certificate.go Cipher.go
./lock -d ./testDirectory  -p testData/unlockingParty/wRSApub -r testData/lockingParty/wECpriv -s ANonTypicalSubjectName
go build unlock.go unlocker.go RSACipher.go cmd.go ECCipher.go certificate.go Cipher.go
./unlock -d ./testDirectory  -p testData/lockingParty/wRSApub -r testData/unlockingParty/wRSApriv -s ANonTypicalSubjectName
