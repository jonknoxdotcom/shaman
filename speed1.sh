#/bin/bash

make build
go install

rm lps.txt

echo Settling...
sleep 5

for i in `seq 10`; do 

echo -n " $i/10"
rm anno.ssf
sleep 3
DEBUG=1 shaman ano desktop.ssf anno.ssf | grep "Anonymisation read" | jq .lps >> lps.txt

done

awk '{ sum += $1 } END { print sum/10 }' lps.txt

