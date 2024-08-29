from samba.credentials import Credentials
from samba.param import LoadParm

import samba
import samba.getopt as options
import optparse
import sys

import xmlschema
import lxml.etree as ET

from client import Service
import common

import logging

logging.basicConfig(level=logging.INFO)

parser = optparse.OptionParser("cli.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

realm = creds.get_realm()

fqdn = '{}.{}'.format(host, realm) if realm.lower() not in host.lower() else host

xs = common.build_xml_schema()

service = Service('Windows/Resource', fqdn, host, credopts.ipaddress, creds)
service_map = {}

service_map['Windows/Resource'] = service

import client

command = client.RootDSEGet(xs, service_map)
output = command.send()

print(output)
decoded = xs.to_dict(output)

domain_dn = decoded['s:Body']['addata:top'][0]['addata:rootDomainNamingContext'][0]['ad:value'][0]['$']

command = client.RootDSEPortLDAP(xs, service_map)
output = command.send()

print(output)

service_map['Windows/ResourceFactory'] = Service('Windows/ResourceFactory',
                                                 fqdn, host,
                                                 credopts.ipaddress,
                                                 creds)

command = client.Create("CN=testuser," + domain_dn,
                        "User",
                        xs, service_map)
output = command.send()
print(output)

command = client.Get("CN=testuser," + domain_dn,
#command = client.Get(domain_dn,
                     xs, service_map)
output = command.send()

print(output)

command = client.Get('11111111-1111-1111-1111-111111111111',
                     xs, service_map)
output = command.send()

print(output)

service_map['Windows/Enumeration'] = Service('Windows/Enumeration',
                                             fqdn, host,
                                             credopts.ipaddress,
                                             creds)
command = client.Enumerate(domain_dn,
                           "(objectClass=user)",
                           "subtree", xs, service_map)
output = command.send_all()

command = client.Delete("CN=testuser," + domain_dn,
                        xs, service_map)
output = command.send()

print(output)
