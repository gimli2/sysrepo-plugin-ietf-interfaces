#!/bin/bash

sysrepocfg --import=create_if.json --format=json --datastore=running ietf-interfaces
sysrepocfg --import=create_system.json --format=json --datastore=startup ietf-system

r=`timeout 1 ../build/stest | grep "destination dir"`
r=`echo $r | awk '{print $5}'`

echo $r

diff -s "$r/eth0.network" "./eth0.network.tmp"
r1=$?
diff -s "$r/eth1.network" "./eth1.network.tmp"
r2=$?

echo "r1=$r1 r2=$r2"

if [ "$r1" == 0 ] && [ "$r2" == 0 ]; then
  echo "Test passed. ;-)"
  exit 0
else
  echo "Test failed, generated config files differ."
  exit 1
fi


exit 0
