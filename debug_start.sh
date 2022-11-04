#!/bin/bash

g_all 'mkdir /var/tmp/debug'
g_all 'fw debug fwd on PDP_LOG_SIZE=50000000'
g_all 'fw debug fwd on PDP_NUM_LOGS=100'
g_all 'fw debug fwd on PEP_LOG_SIZE=50000000'
g_all 'fw debug fwd on PEP_NUM_LOGS=100'
g_all 'rm $FWDIR/log/pdpd.elg.*'
g_all 'rm $FWDIR/log/pepd.elg.*'
echo 'restarting pdpd and pepd and wait 10 seconds'
g_all 'fw kill pdpd ; fw kill pepd ; sleep 10'
g_all 'pdp debug reset; pdp debug on; pdp debug set TRACKER all'
g_all 'pep debug reset; pep debug on; pep debug set TRACKER all'
g_fw ctl debug 0
g_fw ctl set int simple_debug_filter_off 1 -a
g_fw ctl set str simple_debug_filter_addr_1 "1.1.1.1" -a
g_fw ctl debug -buf 99999
g_fw ctl debug -m IDAPI all
g_fw ctl debug -m fw + nac
g_fw ctl debug -m UP + info module connection rulebase
g_fw ctl kdebug -T -f &> /var/tmp/debug/kdebug.txt &


