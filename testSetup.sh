rm -rf testData
rm -rf testDirectory

mkdir testData
mkdir testData/lockingParty
mkdir testDAta/unlockingParty

mkdir -p testDirectory/{A,B}/{{A1,A2},{B1,B2}} 
find testDirectory -type d -exec touch {}/TESTFILE \;

echo 'create files'
find testDirectory -type f -name TESTFILE -exec sh -c 'pwgen 14 1  > "$1"' -- {} \;

./keygen -t ec -s ATypicalSubjectName -pub testData/lockingParty/wECpub -priv testData/lockingParty/wECpriv
./keygen -t rsa -s ATypicalSubjectName -pub testData/lockingParty/wRSApub -priv testData/lockingParty/wRSApriv
./keygen -t ec -s ATypicalSubjectName -pub testData/unlockingParty/wECpub -priv testData/unlockingParty/wECpriv
./keygen -t rsa -s ATypicalSubjectName -pub testData/unlockingParty/wRSApub -priv testData/unlockingParty/wRSApriv

go build lock.go locker.go RSACipher.go cmd.go ECCipher.go certificate.go Cipher.go
go build unlock.go unlocker.go RSACipher.go cmd.go ECCipher.go certificate.go Cipher.go

./lock -d testDirectory  -p testData/unlockingParty/wRSApub -r testData/lockingParty/wECpriv -s ANonTypicalSubjectName
echo 'locked complete'
find testDirectory -type f -name TESTFILE -exec sh -c 'head "$1"; echo '\n'' -- {} \;

./unlock -d testDirectory  -p testData/lockingParty/wECpub -r testData/unlockingParty/wRSApriv -s ANonTypicalSubjectName
echo 'unlock complete'
find testDirectory -type f -name TESTFILE -exec sh -c 'cat -t "$1"' -- {} \;
