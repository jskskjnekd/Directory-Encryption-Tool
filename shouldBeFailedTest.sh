#!/usr/bin/env bash

echo 'should be failed!--------'




./keygen -t ec -s ACACAC -pub testData/lockingParty/wECpub2 -priv testData/lockingParty/wECpriv2
./keygen -t rsa -s ACACAC -pub testData/lockingParty/wRSApub2 -priv testData/lockingParty/wRSApriv2
./keygen -t ec -s ACACAC -pub testData/unlockingParty/wECpub3 -priv testData/unlockingParty/wECpriv3
./keygen -t rsa -s ACACAC -pub testData/unlockingParty/wRSApub3 -priv testData/unlockingParty/wRSApriv3





./lock -d testDirectory  -p testData/unlockingParty/wRSApub3 -r testData/lockingParty/wECpriv2 -s ANonTypicalSubjectName














