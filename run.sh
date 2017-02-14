#/bin/sh

screen -d -m -S sflow
screen -p 0 -X stuff "sflowtool -l | python elephant.py `echo -ne '\015'`"
