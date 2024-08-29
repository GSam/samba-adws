# Tests of ADWS
#
# Copyright (C) Garming Sam <garming@samba.org> 2024
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import optparse
import sys
import base64
import re
import samba

from samba.tests.subunitrun import SubunitOptions, TestProgram
import samba.getopt as options

from samba import gensec

import sys
import os

sys.path.insert(1, os.path.join(sys.path[0], '..'))

import client
from client import Service

import common

xs = common.build_xml_schema()

parser = optparse.OptionParser("tests.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

realm = creds.get_realm()

fqdn = '{}.{}'.format(host, realm) if realm.lower() not in host.lower() else host

#
# Tests start here
#

class BaseTests(samba.tests.TestCase):

    def setUp(self):
        super(BaseTests, self).setUp()

        self.domain_dn = "DC=" + realm.replace(".",",DC=")
        self.service_map = {}

        self.service_map['Windows/Resource'] = Service('Windows/Resource', fqdn, host, credopts.ipaddress, creds)

    def tearDown(self):
        super(BaseTests, self).tearDown()

        for service in self.service_map:
            self.service_map[service].close()

class RootDSEGetTests(BaseTests):

    def test_plain_rootdse(self):
        command = client.RootDSEGet(xs, self.service_map)
        output = command.send()

        decoded = xs.to_dict(output)

class BaseTestsWithOU(BaseTests):

    def setUp(self):
        super(BaseTestsWithOU, self).setUp()

        self.service_map['Windows/ResourceFactory'] = Service('Windows/ResourceFactory', fqdn, host, credopts.ipaddress, creds)

        self.ou = "OU=test_ou," + self.domain_dn
        command = client.Create(self.ou,
                                "organizationalUnit",
                                xs, self.service_map)
        command.send()

    def tearDown(self):
        super(BaseTests, self).tearDown()

        command = client.Delete(self.ou,
                                xs, self.service_map)
        output = command.send()

    def test_pass(self):
        pass

# Important unit running information

TestProgram(module=__name__, opts=subunitopts)
