#!/usr/bin/env python
"""****************************************************************************
* nodeKnock-Client 0.1 by freddyb
*
* this is one of many possible nodeKnock clients, and is meant to be as a
* proof of concept.
*
****************************************************************************"""

from time import time
from hashlib import sha1
from commands import getoutput

execfile('nodeKnock.cfg')

# prepare command
cmd1 = "ping -c 1 -p "
cmd2 = " "+ config['host']

# build pattern
header = "4e444b" # 0x4e', '0x44', '0x4b, NDK
t = int(time()) # timestamp-integer
p_timestamp = hex(t)[2:] # hex, because ping demands this.

#sha1(client_ip + secret + timestamp')
p_hash = sha1( config['own_ip'] + config['secret'] + str(t)).hexdigest()

# build string for execution
pattern = header + p_timestamp + p_hash
execStr = cmd1 + pattern + cmd2
# ping -c1 -p^    ^bytes    ^host

print "Executing", repr(execStr)
print getoutput(execStr)
#DEBUG: print [int(pattern[2*i:2*i+2],16) for i in xrange(len(pattern)/2)]

