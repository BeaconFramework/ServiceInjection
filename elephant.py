###########################################################################
#   Copyright 2016 IBM Corp.
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
############################################################################

import sys
import time
from oslo_config import cfg
import subprocess
import struct
import json

opt_group = cfg.OptGroup(name='sa',
                         title='sflow analayzer configuration')

sa_opts = [
    cfg.StrOpt('ovn_db', default='localhost:6640'),
    cfg.IntOpt('el_duration', default=5),
    cfg.IntOpt('el_bandwidth', default=500),
    cfg.IntOpt('flow_timeout', default=60)
    ]

CONF = cfg.CONF
CONF.register_group(opt_group)
CONF.register_opts(sa_opts, 'sa')

CONF(default_config_files=['sa.conf'])

ELEPHENT_DURATION = CONF.sa.el_duration
ELEPHENT_BANDWIDTH = CONF.sa.el_bandwidth # bytes/sec
FLOW_TIMEOUT = CONF.sa.flow_timeout

flows = {}

def getDatapath(flow):
    eth_src = flow[4][:2] + ':' + flow[4][2:4] + ':' + flow[4][4:6] + ':' + flow[4][6:8] + ':' + flow[4][8:10] + ':' + flow[4][10:12]

    cmd = ['ovsdb-client', '-f', 'json', 'transact', 'tcp:' + CONF.sa.ovn_db, '["OVN_Northbound",{"op":"select","table":"Logical_Port","where":[["addresses","==",\"%s\"]]}]' % eth_src]
    msg = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None).stdout.read().rstrip()

    body = json.loads(msg)

    lp = body[0]['rows'][0]['_uuid'][1]
    lp_match = "[\"uuid\",\"%s\"]" % lp

    cmd = ['ovsdb-client', '-f', 'json', 'transact', 'tcp:' + CONF.sa.ovn_db, '["OVN_Northbound",{"op":"select","table":"Logical_Switch","where":[["ports","includes",%s]]}]' % lp_match]
    msg = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None).stdout.read().rstrip()

    body = json.loads(msg)
    dp = body[0]['rows'][0]['_uuid'][1]

    cmd = ['ovsdb-client', '-f', 'json', 'transact', 'tcp:' + CONF.sa.ovn_db, '["OVN_Southbound",{"op":"select","table":"Datapath_Binding","where":[["external_ids","includes",["map",[["logical-switch",\"%s\"]]]]]}]' % dp]

    msg = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None).stdout.read().rstrip()

    body = json.loads(msg)
    dp = body[0]['rows'][0]['_uuid'][1]

    return dp

def getKeyFromLine(line):
    return "%s:%s-%s:%s" % (line[9], line[14], line[10], line[15])

def isTcpFlow(line):
    if line[11] == '6':
	return True

    return False

def addFlowToSBDB(flow):
    dp = getDatapath(flow)

    match = "eth.type == 0x0800 && ip.proto==6 && ip4.src==%s && tcp.src==%s && ip4.dst==%s && tcp.dst==%s" % (line[9], line[14], line[10], line[15])
	
    cmd = ['ovsdb-client', 'transact', 'tcp:%s' % CONF.sa.ovn_db, '["OVN_Southbound",{"op":"insert","table":"Logical_Flow","row":{"logical_datapath":["uuid",\"%s\"],"pipeline":"egress","priority":50,"table_id":0,"external_ids":["map",[["stage-name","acl"]]],"match":\"%s\","actions":"ip.dscp=8; next;"}}]' % (dp, match)]

    msg = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None).stdout.read().rstrip()

def addTcpFlow(line):
    key = getKeyFromLine(line)

    current_time = time.time()
    
    if key in flows.keys():
	flow = flows[key]

	duration = current_time - flow['start']
	if (int(line[16]) < int(flow['seq'])) or (current_time - flow['time'] <= 0.05):
	    bandwidth = 0
	else :
	    bandwidth = (int(line[16]) - int(flow['seq'])) / (current_time - flow['time'])

	if not flow['is_elephant'] and duration > ELEPHENT_DURATION and bandwidth > ELEPHENT_BANDWIDTH:
	    print "Flow %s is an elephent (duration = %s , bandwidth %s)\n" % (key, duration, bandwidth)
	    flow['is_elephant'] = True
	    addFlowToSBDB(line)

	flow['seq'] = line[16]
	flow['time'] = current_time

    else:
	flow = {'start' : current_time,
	       'time' : current_time,
	       'seq' : line[16],
	       'is_elephant' : False,
	       'line' : line
		}

	flows[key] = flow
	print "Added %s to flows\n" % key

def garbageCollector():
    current_time = time.time()
    removed = []
    for key, flow in flows.iteritems():
	if current_time - flow['time'] > FLOW_TIMEOUT:
	    removed.append(key)

    for key in removed:
	print "Remove flow: %s" % key
	line = flows[key]['line']
	match = "eth.type == 0x0800 && ip.proto==6 && ip4.src==%s && tcp.src==%s && ip4.dst==%s && tcp.dst==%s" % (line[9], line[14], line[10], line[15])
	cmd = ['ovsdb-client', 'transact', 'tcp:%s' % CONF.sa.ovn_db, '["OVN_Southbound",{"op":"delete","table":"Logical_Flow","where":[["match","==",\"%s\"]]}]' % match]

	msg = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None).stdout.read().rstrip()

	del flows[key]

while 1:

    line = sys.stdin.readline()
    if line == '':
        break
    line = line.split(',')
    if line[0] == 'FLOW' and isTcpFlow(line):
	addTcpFlow(line)

    garbageCollector()
