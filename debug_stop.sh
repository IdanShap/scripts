#!/bin/bash

fw ctl debug 0
fw ctl set int simple_debug_filter_off 1 -a
g_all 'fw debug fwd on PDP_LOG_SIZE=10000000'
g_all 'fw debug fwd on PDP_NUM_LOGS=10'
g_all 'fw debug fwd on PEP_LOG_SIZE=10000000'
g_all 'fw debug fwd on PEP_NUM_LOGS=10'

mkdir /var/tmp/debug/second_sgm
rgcopy -b 01_02 /var/tmp/debug/* /var/tmp/debug/second_sgm
