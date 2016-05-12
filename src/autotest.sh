#!/bin/sh

check () {
dd if=$1 2> /dev/null | ./tea -e -m $3 | ./tea -d -m $3 | dd of=$2 2> /dev/null
diff $1 $2 > /dev/null

if [ "$?" = "0" ]; then
     echo "Test: $1 $2 $3: OK"
else
     echo "Test: $1 $2 $3: ERROR"
fi
}
./tea -g -e -c

check "tmp.txt" "tmp_res.txt" "ebc"
check "tmp.txt" "tmp_res.txt" "cbc"
check "tmp.txt" "tmp_res.txt" "pcbc"
check "tmp.txt" "tmp_res.txt" "cfb"
check "tmp.txt" "tmp_res.txt" "ofb"
check "tmp.txt" "tmp_res.txt" "ebc"

