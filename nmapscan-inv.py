#!/usr/bin/env python

# (c) 2019, Vincent Freret <vfreret@redhat.com>
#
# This file is part of Ansible,
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from subprocess import Popen, PIPE
import sys
import json
import socket
import nmap

if sys.argv[2] == "":
	print("Syntax error : <SUBNET> <PORT> [--list | --debug] arguments needed. e.g : 192.168.1.0/24 ssh")


result = {}
result['all'] = {}


if sys.argv[3] == "--debug":
	print('Arguments :  --network='+str(sys.argv[1])+' --port='+str(sys.argv[2])+'')
	nm = nmap.PortScanner()
	nm.scan(hosts=''+str(sys.argv[1])+'', arguments='-p '+str(sys.argv[2])+' --open')
	traceh = nm.all_hosts()
	print(str(traceh))
	x=0
	for i in traceh:
		print(''+str(i)+'')
		x=int(x)+1

	print (''+str(x)+' IPs Addresses found with '+str(sys.argv[2])+' port open on network '+str(sys.argv[1])+'')
	print("")

	print ("Details for each hosts :")

	for host in traceh:
		n = nmap.PortScanner()
		hr=n.scan(hosts=host, arguments='-sP')
		print(str(hr))


	

	result['all']['hosts'] = [x[:] for x in traceh]
	result['all']['vars'] = {}
	result['all']['vars']['ansible_connection'] = 'nmap_'+str(sys.argv[2])+'_open'

	print ("JSON result for Ansible :")
	print(json.dumps(result))

if sys.argv[3] == "--list":
	nm = nmap.PortScanner()
	nm.scan(hosts=''+str(sys.argv[1])+'', arguments='-p '+str(sys.argv[2])+' --open')
	traceh = nm.all_hosts()
	#print(str(traceh))
	
	for host in traceh:
		n = nmap.PortScanner()
		hr=n.scan(hosts=host, arguments='-sP')
		#print(str(hr))

	result['all']['hosts'] = [x[:] for x in traceh]
	result['all']['vars'] = {}
	result['all']['vars']['ansible_connection'] = 'nmap_'+str(sys.argv[2])+'_open'
	print(json.dumps(result))



