#!/usr/bin/env bash


mkdir testData
mkdir testData/lockingParty
mkdir testData/unlockingParty

echo "        -----create files for failed test----"
mkdir -p testDirectoryFAIL/{A,B}/{{A1,A2},{B1,B2}}
find testDirectoryFAIL -type d -exec touch {}/TESTFILE \;
find testDirectoryFAIL -type f -name TESTFILE -exec sh -c 'dd if=/dev/random of="$1" bs=10 count=50' -- {} \;



./keygen -t ec -s TTTTTTT -pub testData/lockingParty/wECpub22 -priv testData/lockingParty/wECpriv22
./keygen -t rsa -s TTTTTTT -pub testData/lockingParty/wRSApub22 -priv testData/lockingParty/wRSApriv22
./keygen -t ec -s TTTTTTT -pub testData/unlockingParty/wECpub33 -priv testData/unlockingParty/wECpriv33
./keygen -t rsa -s TTTTTTT -pub testData/unlockingParty/wRSApub33 -priv testData/unlockingParty/wRSApriv33






./lock -d testDirectoryFAIL  -p testData/unlockingParty/wRSApub33 -r testData/lockingParty/wECpriv22 -s TTTTTTT

echo "unlocking......."



./unlock -d testDirectoryFAIL  -p testData/lockingParty/wECpub22 -r testData/unlockingParty/wRSApriv33 -s TTTTTTTAAAAAAAA


