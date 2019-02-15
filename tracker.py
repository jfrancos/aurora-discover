#!/usr/bin/python3

#todo:
#write script to put nmap info into db

from glob import glob
import pprint
import re
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from dotenv import load_dotenv
from pymongo import MongoClient
import os
from pymongo import UpdateOne
from datetime import datetime, date, timedelta

num_ports = 15
num_days = 30
test = False

timestamp = datetime.utcnow()
pp = pprint.PrettyPrinter()
load_dotenv()
mongo_db = os.getenv("DB")
ips = MongoClient(mongo_db).snacks.ips

if test:
	num_ports = 4
	num_days = 2

# Get [num_ports] most frequently used ports
# ports = "80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080"
services_regex = re.compile('[^#\s]+\s+\d+/tcp')
ports = open("/snap/nmap/current/share/nmap/nmap-services")
ports = [port.split() for port in ports if services_regex.match(port)]
ports = sorted(ports, key=lambda col: col[2], reverse=True)[:num_ports]
ports = ",".join([(col[1]).split("/")[0] for col in ports])

suffix = '-active_IPs.csv'
path = '/home/jfrancos/Dropbox/Aurora/Active-IP/'
first_date = path + (date.today() - timedelta(num_days)).isoformat() + suffix
files = sorted(glob(path + "*" + suffix))
skip_name = path + '2019-02-04' + suffix
files = [file for file in files if file >= first_date and file != skip_name]
data_regex = re.compile(',([\d.]+),')
ist_regex = re.compile(',(.*),.*,.*,.*-NET,')

IP_set = set()
ist_ips = set()

for file_name in files:
    file = open(file_name, "r")
    for line in file:
        search = data_regex.match(line)
        ist = ist_regex.match(line)
        if ist:
        	ist_ips.add(ist[1])
        elif search:
            IP_set.add(search[1])

if test:
	IP_set = set(sorted(list(IP_set))[:4])
else:
	IP_set = set(sorted(list(IP_set)))

recently_set = {"$expr" : {"$gt" : [{ "$arrayElemAt" : ["$timeline.time", -1]}, datetime.utcnow() - timedelta(1) ]}}

down = {"$expr" : {"$eq" : [{ "$arrayElemAt" : ["$timeline.up", -1]}, False ]}}
recently_down = ips.find({"$and" : [recently_set, down]})
recently_down = [host['ip'] for host in recently_down]

up = {"$expr" : {"$eq" : [{ "$arrayElemAt" : ["$timeline.up", -1]}, True ]}}
recently_up = ips.find({"$and" : [recently_set, up]})
recently_up = [host['ip'] for host in recently_up]

# pp.pprint(recently_down)
# pp.pprint(recently_up)
# pp.pprint(IP_set)

up_hosts = set()
writes = []

nmap_options = f'--send-ip -PE -PS{ports} -PA{ports} -sn -PP -n'
nm = NmapProcess(list(IP_set), nmap_options, fqp='/snap/bin/nmap')
nm.sudo_run()
print(nm.stderr)

report = NmapParser.parse(nm.stdout)

up_hosts = [host.ipv4 for host in report.hosts if host.is_up() and host.ipv4 not in recently_up]
down_hosts = [host.ipv4 for host in report.hosts if not host.is_up() and host.ipv4 not in recently_down]

for host in up_hosts:
	filter = {"ip": { "$eq" : host }}
	update = {"$push" : { "timeline" : { "time" : timestamp, "up" : True }}}
	writes.append(UpdateOne(filter, update, upsert=True ))

for host in down_hosts:
	filter = {"ip": { "$eq" : host }}
	update = {"$push" : { "timeline" : { "time" : timestamp, "up" : False }}}
	writes.append(UpdateOne(filter, update, upsert=True ))

# if test:
# 	print(writes)
# else:
	# ips.bulk_write(writes)

if len(writes) > 0:
	ips.bulk_write(writes)
print(writes)


# def callback(scan):
# report = find_hosts([host.ipv4 for host in up_hosts], '-Pn -A -n')#, callback=callback)
# report = find_hosts(["18.93.6.23", "18.33.0.158"], '-Pn -O -Sv -Sc -n')#, callback=callback)

# for host in report.hosts:
# 	pp.pprint(host.ipv4)
# 	pp.pprint(host.os)
# 	pp.pprint(host.services)
# 	pp.pprint(host.scripts_results)
# 	# pp.pprint(host.get_dict())
# 	# pp.pprint(host.os_class_probabilities())
# 	matches = host.os_match_probabilities()
# 	for match in matches:
# 		pp.pprint(match.accuracy)
# 		pp.pprint(match.name)
# 	pp.pprint(host.os_match_probabilities())
