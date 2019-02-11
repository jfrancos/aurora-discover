#!/usr/bin/python3

import csv
from glob import glob
import pprint
import re
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from dotenv import load_dotenv
from pymongo import MongoClient
import os
from pymongo import InsertOne, DeleteOne, ReplaceOne, UpdateOne
from datetime import datetime

pp = pprint.PrettyPrinter()
load_dotenv()
client = MongoClient(os.getenv("DB"))
db = client.snacks
ips = db.snacks

services_regex = re.compile('[^#\s]+\s+\d+/tcp')
ports = open("/snap/nmap/current/share/nmap/nmap-services")
ports = [port.split() for port in ports if services_regex.match(port)]
ports = sorted(ports, key=lambda col: col[2], reverse=True)[:15]
ports = ",".join([(col[1]).split("/")[0] for col in ports])

path = '/home/jfrancos/Dropbox/Aurora/Active-IP/'
first_date = path + '2018-12-12-active_IPs.csv'
files = sorted(glob(path + "*-active_IPs.csv"))
skip_name = path + '2019-02-04-active_IPs.csv'
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

IP_set = set(sorted(list(IP_set)))

up_hosts = set()
writes = []

def find_hosts(targets, options):
	nm = NmapProcess(list(targets), options, fqp='/snap/bin/nmap')
	nm.sudo_run()
	print(nm.stderr)
	return NmapParser.parse(nm.stdout)

report = find_hosts(list(IP_set), f'--send-ip -PE -PS{ports} -PA{ports} -sn -PP -n')
for host in report.hosts:
	if host.is_up():
		up_hosts.add(host)
		IP_set.remove(host.ipv4)
# print(f"{len(up_hosts)} hosts found")

for host in up_hosts:
	writes.append(UpdateOne({"ip": { "$eq" : host.ipv4 }}, {"$push" : { "timeline" : { "time" : datetime.fromtimestamp(report.endtime), "up" : True }}}, upsert=True ))

for host in IP_set:
	writes.append(UpdateOne({"ip": { "$eq" : host }}, {"$push" : { "timeline" : { "time" : datetime.fromtimestamp(report.endtime), "up" : False }}}, upsert=True ))

ips.bulk_write(writes)

# def callback(scan):
# report = find_hosts(up_hosts, '-Pn -A -n', callback=callback)
# for host in report.hosts:
# 	# pp.pprint(host)
# 	# pp.pprint(host.os)
# 	# pp.pprint(host.os.name)
# 	pp.pprint(host.get_dict())
# 	# pp.pprint(host.os_class_probabilities())
# 	matches = host.os_match_probabilities()
# 	for match in matches:
# 		pp.pprint(match.accuracy)
# 		pp.pprint(match.name)
# 	# pp.pprint(host.os_match_probabilities())
