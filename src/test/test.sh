#!/bin/sh
TESTDIR=$1
DAEMON=../primwatchd
PRIMDNS=../primwatch_primdns
PID=/tmp/pid
RES=/tmp/res
QUERY=/tmp/query

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
    echo ${PRIMDNS} $1 IN $2 > ${QUERY}
    ${PRIMDNS} $1 IN $2 > ${RES}
}

check() {
    n=0
    r=0
    while read l;
    do
       if [ "${n}" == "0" ]; then
           if [ "${l}" != "$1" ]; then
               echo "response mismatch (actual ${l}, expected $1)"
               stop_daemon
               exit 1
           fi
       else
           m=$(echo "${l}" | egrep "$3")
           if [ -z "${m}" ]; then
               echo "record mismatch (actual ${l}, expected $3)"
               stop_daemon
               exit 1
           fi
           r=$((${r} + 1))
       fi
       n=$((${n} + 1))
    done < ${RES}
    if [ "${r}" != "$2" ]; then
        echo "record count mismatch (actual ${r}, expected $2)"
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
query 12345678901234567890123456789012345678901234567890123456789123.sub1.example.com CNAME
check 0 1 "12345678901234567890123456789012345678901234567890123456789123.sub1.example.com 60 IN CNAME h1.sub2.example.com"

echo "test 4"
query 12345678901234567890123456789012345678901234567890123456789123.happy-my-home-east-tokyo-japan.example.com CNAME
check 0 1 "12345678901234567890123456789012345678901234567890123456789123.happy-my-home-east-tokyo-japan.example.com 60 IN CNAME h1.sub3.example.com"

echo "test 5"
query sub1.example.com A
check 0 1 "sub1.example.com 60 IN CNAME h1.sub2.example.com"

echo "test 6"
query hoge.sub1.example.com A
check 0 1 "hoge.sub1.example.com 60 IN CNAME h1.sub2.example.com"

echo "test 7"
query 12345678901234567890123456789012345678901234567890123456789123.sub1.example.com A
check 0 1 "12345678901234567890123456789012345678901234567890123456789123.sub1.example.com 60 IN CNAME h1.sub2.example.com"

echo "test 8"
query 12345678901234567890123456789012345678901234567890123456789123.happy-my-home-east-tokyo-japan.example.com A
check 0 1 "12345678901234567890123456789012345678901234567890123456789123.happy-my-home-east-tokyo-japan.example.com 60 IN CNAME h1.sub3.example.com"

echo "test 9"
query sub1.example.com PTR
check 0 0 ""

echo "test 10"
query hoge.sub1.example.com PTR
check 0 0 ""

echo "test 11"
query sub1.example.com ANY
check 0 1 "sub1.example.com 60 IN CNAME h1.sub2.example.com"

echo "test 12"
query h1.sub2.example.com CNAME
check 0 0 ""

echo "test 13"
query hoge.h1.sub2.example.com CNAME
check 3 0 ""

echo "test 14"
query h1.sub2.example.com A
check 0 2 "h1.sub2.example.com 10 IN A 10.0.0."

echo "test 15"
query hoge.h1.sub2.example.com A
check 3 0 ""

echo "test 16"
query h1.sub2.example.com PTR
check 0 0 ""

echo "test 17"
query hoge.h1.sub2.example.com PTR
check 3 0 ""

echo "test 18"
query 2.0.0.10.in-addr.arpa PTR
check 0 1 "2.0.0.10.in-addr.arpa 10 IN PTR n2.sub2.example.com"

echo "test 19"
query 3.0.0.10.in-addr.arpa PTR
check 0 0 ""

echo "test 20"
query h1.sub2.example.com ANY
check 0 2 ".*"

echo "test 21"
query 4.0.0.10.in-addr.arpa ANY
check 0 1 ".*"

echo "test 22"
query www.sub3.example.com CNAME
check 0 1 "www.sub3.example.com 1800 IN CNAME h1.sub2.example.com"

echo "test 23"
query www.www.sub3.example.com CNAME
check 3 0 ""

echo "test 24"
query www.sub3.example.com A
check 0 1 "www.sub3.example.com 1800 IN CNAME h1.sub2.example.com"

echo "test 25"
query www.www.sub3.example.com A
check 3 0 ""

echo "test 26"
query h1.sub3.example.com A
check 0 2 "h1.sub3.example.com 10 IN A 10.1.0."

echo "test 27"
query hoge.h1.sub3.example.com A
check 3 0 ""

echo "test 28"
query h1.sub3.example.com PTR 
check 0 0 ""

echo "test 29"
query hoge.h1.sub3.example.com PTR 
check 3 0 ""

echo "test 30"
query h1.sub3.example.com ANY
check 0 3 ".*"

echo "test 31"
query hoge.h1.sub3.example.com ANY
check 3 0 ""

echo "test 32"
query 1.0.1.10.in-addr.arpa PTR
check 0 1 "1.0.1.10.in-addr.arpa 10 IN PTR nn1.sub3.example.com"

echo "test 33"
query 2.0.1.10.in-addr.arpa PTR
check 0 0

echo "test 34"
query 3.0.1.10.in-addr.arpa ANY
check 0 1 ".*"

echo "test 35"
query h1.sub4.example.com CNAME
check 0 0 ""

echo "test 36"
query h1.sub4.example.com A
check 0 2 "h1.sub4.example.com 10 IN A 10.2.0."

echo "test 37"
query h1.sub4.example.com PTR
check 0 0 ""

echo "test 38"
query h1.sub4.example.com ANY
check 0 2 ".*"

echo "test 39"
query h2.sub4.example.com A
check 0 0 ""

echo "test 40"
query h3.sub4.example.com A
check 0 2 "h3.sub4.example.com 10 IN A 10.2.0."

echo "test 41"
query h1.sub5.example.com CNAME
check 0 0 ""

echo "test 42"
query h1.sub5.example.com A
check 0 2 "h1.sub5.example.com 10 IN A 10.3.0."

echo "test 43"
query h1.sub5.example.com ANY
check 0 2 ".*"

echo "test 44"
query h2.sub5.example.com A
check 0 0 ""

echo "test 45"
query h3.sub5.example.com A
check 0 1 "h3.sub5.example.com 10 IN A 10.3.0.1"

echo "test 46"
query h1.sub7.example.com CNAME
check 0 0 ""

echo "test 47"
query h1.sub7.example.com A
check 0 2 "h1.sub7.example.com 10 IN A 10.6.0."

echo "test 48"
query h1.sub7.example.com PTR
check 0 0 ""

echo "test 49"
query h1.sub7.example.com ANY
check 0 2 "h1.sub7.example.com 10 IN A 10.6.0."

echo "test 50"
query www.h1.sub7.example.com A
check 0 2 "www.h1.sub7.example.com 10 IN A 10.6.0."

echo "test 51"
query hoge.sub1.example.com ANY
check 0 1 "hoge.sub1.example.com 60 IN CNAME h1.sub2.example.com"

echo "test 52"
query www.h1.sub7.example.com ANY
check 0 2 "www.h1.sub7.example.com 10 IN A 10.6.0."

echo "test 53"
query PiyOpiYo.seRviCe.miX2.exAmpLe.cOm CNAME
check 0 1 "PiyOpiYo.seRviCe.miX2.exAmpLe.cOm 60 IN CNAME service.mix1.example.com"

echo "test 54"
query miX2.ExAmpLe.cOM CNAME
check 0 1 "miX2.ExAmpLe.cOM 60 IN CNAME hack.mix1.example.com"

echo "test 55"
query HogeHoge.SeRvice.miX1.ExAmpLe.cOM A
check 0 1 "HogeHoge.SeRvice.miX1.ExAmpLe.cOM 10 IN A 10.6.0.1"

echo "test 56"
query MeTa.HacK.Mix1.ExAmpLe.cOM A
check 0 1 "MeTa.HacK.Mix1.ExAmpLe.cOM 10 IN A 10.6.0.2"

echo "test 57"
query hOST1.seRvIcE.miX1.ExAmpLe.cOM A
check 0 2 "hOST1.seRvIcE.miX1.ExAmpLe.cOM 10 IN A 10.6.0.1"

echo "test 58"
query 1.0.1.11.iN-AdDr.aRpA PTR
check 0 1 "1.0.1.11.iN-AdDr.aRpA 10 IN PTR nn1.mix1.example.com"

echo "test 59"
query 2.0.1.11.iN-AdDr.aRpA PTR
check 0 1 "2.0.1.11.iN-AdDr.aRpA 10 IN PTR nn2.mix1.example.com"

#finalize
stop_daemon
