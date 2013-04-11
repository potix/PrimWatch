#!/bin/sh

i=0

while  [ ${i} -lt "10000" ]
do
../primwatch_primdns example.com IN A > /dev/null
i=$((${i} + 1))
done
