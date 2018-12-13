#!/usr/bin/env bash

rm -rf testData
rm -rf testDirectory

mkdir testData
mkdir testData/lockingParty
mkdir testData/unlockingParty


echo 'create files'
mkdir -p testDirectory/{A,B}/{{A1,A2},{B1,B2}}
find testDirectory -type d -exec touch {}/TESTFILE \;
find testDirectory -type f -name TESTFILE -exec sh -c 'dd if=/dev/random of="$1" bs=10 count=50' -- {} \;

./keygen -t ec -s ATypicalSubjectName -pub testData/lockingParty/wECpub -priv testData/lockingParty/wECpriv
./keygen -t rsa -s ATypicalSubjectName -pub testData/lockingParty/wRSApub -priv testData/lockingParty/wRSApriv
./keygen -t ec -s ATypicalSubjectName -pub testData/unlockingParty/wECpub -priv testData/unlockingParty/wECpriv
./keygen -t rsa -s ATypicalSubjectName -pub testData/unlockingParty/wRSApub -priv testData/unlockingParty/wRSApriv

echo 'Before Encryption, the sha256 sum of the directory is'
checksumdir testDirectory

./lock -d testDirectory  -p testData/unlockingParty/wRSApub -r testData/lockingParty/wECpriv -s ATypicalSubjectName    #ANonTypicalSubjectName
echo 'locked complete'
#find testDirectory -type f -name TESTFILE -exec sh -c 'head "$1"; echo '\n'' -- {} \;

./unlock -d testDirectory  -p testData/lockingParty/wECpub -r testData/unlockingParty/wRSApriv -s   ATypicalSubjectName #ANonTypicalSubjectName
echo 'unlock complete'
#find testDirectory -type f -name TESTFILE -exec sh -c 'cat -t "$1"' -- {} \;

echo 'After Encryption, the sha256 sum of the directory is'
checksumdir testDirectory












