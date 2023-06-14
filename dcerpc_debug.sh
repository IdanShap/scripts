#! /bin/bash

unset TMOUT

fw ctl set int cmi_dump_buffer 1
fw ctl get int cmi_dump_buffer

fw ctl set int simple_debug_filter_off 1 -a
fw ctl set str simple_debug_filter_saddr_1 "$1" -a
fw ctl set str simple_debug_filter_daddr_1 "$2" -a
fw ctl set str simple_debug_filter_saddr_2 "$2" -a
fw ctl set str simple_debug_filter_daddr_2 "$1" -a

fw ctl debug -buf 32768
fw ctl debug -m fw + cmi advp spii aspii conn drop vm
fw ctl debug -m UP + all
nohup fw ctl kdebug -T -f &> kdebug.txt &

nohup tcpdump -s0 -w dce_rpc.pcap -enni any -e "host $1 and host $2 and port 135 or portrange 10000-65000" &

trap ctrl_c INT
function ctrl_c() {
    echo "** Trapped CTRL-C"
    fw ctl debug 0
    fw ctl set int simple_debug_filter_off 1 -a
    kill -2 %2
    exit 0
}

while true 
do
    sleep 1
    echo -n "."
done 