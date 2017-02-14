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
    eth_src = flow['srcMAC'][:2] + ':' + flow['srcMAC'][2:4] + ':' + flow['srcMAC'][4:6] + ':' + flow['srcMAC'][6:8] + ':' + flow['srcMAC'][8:10] + ':' + flow['srcMAC'][10:12]

    cmd = ['ovsdb-client', '-f', 'json', 'transact', 'tcp:' + CONF.sa.ovn_db, '["OVN_Northbound",{"op":"select","table":"Logical_Port","where":[["port_security","==",\"%s\"]]}]' % eth_src]
    print cmd
    msg = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None).stdout.read().rstrip()

    body = json.loads(msg)
    print body
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

def getKeyFromFlow(flow):
    return "%s:%s-%s:%s" % (flow['srcIP'], flow['TCPSrcPort'], flow['dstIP'], flow['TCPDstPort'])

def isTcpFlow(flow):
    if 'IPProtocol' in flow and flow['IPProtocol'] == '6':
	return True

    return False

def addFlowToSBDB(sample):
    dp = getDatapath(sample)

    match = "eth.type == 0x0800 && ip.proto==6 && ip4.src==%s && tcp.src==%s && ip4.dst==%s && tcp.dst==%s" % (sample['srcIP'], sample['TCPSrcPort'], sample['dstIP'], sample['TCPDstPort'])
	
    cmd = ['ovsdb-client', 'transact', 'tcp:%s' % CONF.sa.ovn_db, '["OVN_Southbound",{"op":"insert","table":"Logical_Flow","row":{"logical_datapath":["uuid",\"%s\"],"pipeline":"ingress","priority":50,"table_id":1,"external_ids":["map",[["stage-name","switch_in_pre_acl"]]],"match":\"%s\","actions":"ip.dscp=64; next;"}}]' % (dp, match)]

    print "%s \n" % cmd
    msg = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None).stdout.read().rstrip()

def addTcpFlow(sample):
    key = getKeyFromFlow(sample)

    current_time = time.time()
    
    if key in flows.keys():
	flow = flows[key]

	duration = current_time - flow['start']
	if (int(sample['TCPSeq']) < int(flow['TCPSeq'])) or (current_time - flow['time'] <= 0.05):
	    bandwidth = 0
	else :
            bandwidth = (int(sample['TCPSeq']) - int(flow['TCPSeq'])) / (current_time - flow['time'])

	if not flow['is_elephant'] and duration > ELEPHENT_DURATION and bandwidth > ELEPHENT_BANDWIDTH:
	    print "Flow %s is an elephent (duration = %s , bandwidth %s)\n" % (key, duration, bandwidth)
	    flow['is_elephant'] = True
	    addFlowToSBDB(sample)

	flow['TCPSeq'] = sample['TCPSeq']
	flow['time'] = current_time

    else:
	flow = {'start' : current_time,
	       'time' : current_time,
	       'TCPSeq' : sample['TCPSeq'],
	       'is_elephant' : False,
	       'sample' : sample 
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
	sample = flows[key]['sample']
	match = "eth.type == 0x0800 && ip.proto==6 && ip4.src==%s && tcp.src==%s && ip4.dst==%s && tcp.dst==%s" % (sample['srcIP'], sample['TCPSrcPort'], sample['dstIP'], sample['TCPDstPort'])
	cmd = ['ovsdb-client', 'transact', 'tcp:%s' % CONF.sa.ovn_db, '["OVN_Southbound",{"op":"delete","table":"Logical_Flow","where":[["match","==",\"%s\"]]}]' % match]

	msg = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None).stdout.read().rstrip()

	del flows[key]

def read_line():
    line = sys.stdin.readline()

    if line == '':
        exit()

    return line.split(' ')

while 1:
    
    line = read_line()

    flow = {}

    if(line[7] == 'startSample'):
        while line[7] != 'endSample':
            line = read_line()
            flow[line[7]] = line[8][:-1]

    if isTcpFlow(flow):
        addTcpFlow(flow)

    garbageCollector()
