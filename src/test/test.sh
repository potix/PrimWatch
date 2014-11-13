#!/bin/sh
TESTDIR=$1

cd ${TESTDIR}




i=0

while  [ ${i} -lt "10000" ]
do
../primwatch_primdns aa.test.com IN A > /dev/null
i=$((${i} + 1))
done
~
~

