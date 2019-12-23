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

result = {}
result['all'] = {}

nm = nmap.PortScanner()
print('Arguments :  --network='+str(sys.argv[1])+'')

#pipe = Popen(['/usr/bin/virt-dnsdiscover --hosts --dns='+str(sys.argv[1])+' --network='+str(sys.argv[2])+''], stdout=PIPE, universal_newlines=True)
#result['all']['hosts'] = [x[:-1] for x in pipe.stdout.readlines()]
#result['all']['vars'] = {}
#result['all']['vars']['ansible_connection'] = 'libvirt_kvm_guest'
tsc={}
#for i in range(1, 254):
#	ip=str(sys.argv[1])+"."+str(i)
#	host = socket.getfqdn(ip)
#	print(str(host))
#	nm.scan(str(host), '22')      # scan host 127.0.0.1, ports from 22 to 443
#
#	nm.scaninfo()                       # get nmap scan informations {'tcp': {'services': '22-443', 'method': 'connect'}}
#	h=nm.all_hosts()                      # get all hosts that were scanned
#	print (nm[str(h)].state())                   # get command line used for the scan : nmap -oX - -p 22-443 127.0.0.1
#	tsc=nm.scaninfo() 		# get nmap scan informations {'tcp': {'services': '22-443', 'method': 'connect'}}
#	print (str(tsc))
#	result['all'][int(i)] = str(host)
#	i=i+1

nm = nmap.PortScanner()
nm.scan(hosts=''+str(sys.argv[1])+'.0/24', arguments="-p 22 --open")
traceh = nm.all_hosts()
print(str(traceh))


# a more usefull example :
for i in range(1, 254):
    nm = nmap.PortScanner()
    ip=str(sys.argv[1])+"."+str(i)
    host=ip
    nm.scan(host, '22')      # scan host 127.0.0.1, ports from 22 to 443
    #nm.command_line()                   # get command line used for the scan : nmap -oX - -p 22-443 127.0.0.1
    #nm.scaninfo() 
    #nm.all_hosts()                      # get all hosts that were scanned
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())

    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

result['all']['vars'] = {}
result['all']['vars']['ansible_connection'] = 'libvirt_kvm_guest'

print(str(result))

if len(sys.argv) == 3 :
    print(json.dumps({'ansible_connection': 'libvirt_kvm_guest'}))
else:
    sys.stderr.write("Syntax is invalid, argument <network> required.\n")

