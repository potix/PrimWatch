#!/bin/sh
TESTDIR=$1
DAEMON=../primwatchd
PRIMDNS=../primwatch_primdns
PID=/tmp/pid
RES=/tmp/res

start_daemon() {
    ${DAEMON} -c $1 -F &
    child=$!
    echo start daemon ${child}
    echo -n ${child} > ${PID}
    sleep 11
}

stop_daemon() {
    kill $(cat ${PID})
}

query() {
    ${PRIMDNS} $1 IN $2 > ${RES}
}

check() {
    n=0
    r=0
    while read l;
    do
       if [ "${n}" == "0" ]; then
           if [ "${l}" != "$1" ]; then
               echo "response mismatch (${l}, $1)"
               stop_daemon
               exit 1
           fi
       else
           m=$(echo "${l}" | egrep "$3")
           if [ -z "${m}" ]; then
               echo "record mismatch (${l}, $3)"
               stop_daemon
               exit 1
           fi
           r=$((${r} + 1))
       fi
       n=$((${n} + 1))
    done < ${RES}
    if [ "${r}" != "$2" ]; then
        echo "record count mismatch (${r}, $2)"
        stop_daemon
        exit 1
    fi 
}

# initialize
cd ${TESTDIR}
start_daemon ./conf/primwatchd.conf


echo "test 1"
query sub1.example.com CNAME
check 0 1 "sub1.example.com 60 IN CNAME h1.sub2.example.com"

echo "test 2"
query hoge.sub1.example.com CNAME
check 0 1 "hoge.sub1.example.com 60 IN CNAME h1.sub2.example.com"

echo "test 3"
query hoge.sub1.example.com A
check 0 0 ""

echo "test 4"
query hoge.sub1.example.com PTR
check 0 0 ""

echo "test 5"
query hoge.sub1.example.com ANY
check 0 1 ".*"








#finalize
stop_daemon



#i=0
#
#while  [ ${i} -lt "10000" ]
#do
#../primwatch_primdns aa.test.com IN A > /dev/null
#i=$((${i} + 1))
