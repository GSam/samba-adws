#!/usr/bin/env python
# coding=utf8
from __future__ import print_function, unicode_literals, absolute_import

import sys
import base64
import unittest
from io import BytesIO, StringIO

from helperlib import print_hexdump

from wcf.records import dump_records, print_records
from wcf.xml2records import XMLParser

from adws import sambautils
from adws.xmlutils import compare_xml


class ADWSTest(unittest.TestCase):

    def setUp(self):
        self.samdb = sambautils.SamDBHelper()

    def tearDown(self):
        pass

    def test_attr_xml_render(self):
        """
        Make sure xml render is working fine
        """
        attr = sambautils.LdapAttr(
            'configurationNamingContext',
            ['MYDN'],
            'DSDNString',
            xsi_type='xsd:string',
        )

        actual_xml = attr.to_xml()

        expected_xml = """
        <addata:configurationNamingContext LdapSyntax="DSDNString">
            <ad:value xsi:type="xsd:string">MYDN</ad:value>
        </addata:configurationNamingContext>
        """
        self.assertTrue(compare_xml(actual_xml, expected_xml))

    def test_attr_xml_render_different_values(self):
        """
        Make sure we didn't hardcode values.
        """
        attr = sambautils.LdapAttr(
            'configurationNamingContext2',
            ['MYDN2'],
            'DSDNString2',
            xsi_type='ns:somethingelse',
        )

        actual_xml = attr.to_xml()

        expected_xml = """
        <addata:configurationNamingContext2 LdapSyntax="DSDNString2">
            <ad:value xsi:type="ns:somethingelse">MYDN2</ad:value>
        </addata:configurationNamingContext2>
        """
        self.assertTrue(compare_xml(actual_xml, expected_xml))

    def test_attr_xml_render_base64(self):
        """
        Make sure base64Binary attr is base64 encoded.
        """
        guid = '1234567890'

        attr = sambautils.LdapAttr(
            'objectGUID',
            [guid],
            'OctetString',
            xsi_type='xsd:base64Binary',
        )

        actual_xml = attr.to_xml()

        expected_xml = """
        <addata:objectGUID LdapSyntax="OctetString">
           <ad:value xsi:type="xsd:base64Binary">{}</ad:value>
        </addata:objectGUID>
        """.format(base64.b64encode(guid))
        self.assertTrue(compare_xml(actual_xml, expected_xml))

    def test_root_dse_xml(self):
        """
        Make sure all LDAP and Sythetic attrs are included in rootDSE xml.
        """
        result = self.samdb.search_scope_base(base='')
        msg = result[0]
        attrs = set(msg.keys()) - set(['dn', 'vendorName']) & set(sambautils.SYNTHETIC_ATTRS)
        xml = self.samdb.render_root_dse_xml(MessageID='1234')
        for attr in attrs:
            self.assertIn(attr, xml)

    def test_wcf_record(self):
        xml = '<s:Envelope><b:Body></b:Body></s:Envelope>'
        records = XMLParser.parse(xml)
        print(records)
        # [<PrefixDictionaryElementSRecord(type=0x56)>]
        payload = dump_records(records)
        print_hexdump(payload, colored=True, file=sys.stderr)
        out = StringIO()
        print_records(records, fp=out)
        xml2 = out.getvalue()
        self.assertTrue(compare_xml(xml, xml2))


if __name__ == '__main__':
    unittest.main()
