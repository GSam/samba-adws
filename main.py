#!/usr/bin/env python2
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import
from datetime import datetime
from io import BytesIO, StringIO
import socket
import logging
import sys
import binascii
import threading
import warnings

from nettcp.nmf import Record as NMFRecord, register_types

from adws import sambautils

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

from nettcp.stream.socket import SocketStream
from nettcp.nmf import (Record, EndRecord, KnownEncodingRecord,
                  UpgradeRequestRecord, UpgradeResponseRecord,
                  PreambleEndRecord, PreambleAckRecord,
                  SizedEnvelopedMessageRecord,
                  register_types)
try:
    from nettcp.stream.gssapi import GSSAPIStream, GENSECStream
except ImportError:
    warnings.warn('gssapi not installed, no negotiate protocol available')
    GSSAPIStream = None

try:
    from helperlib import print_hexdump
except ImportError:
    warnings.warn('python-helperlib not installed, no hexdump available (https://github.com/bluec0re/python-helperlib)')
    print_hexdump = False


FORMAT = '%(levelname)s %(asctime)s %(pathname)s #%(lineno)d: %(message)s'
logging.basicConfig(level=logging.CRITICAL, format=FORMAT)
log = logging.getLogger(__name__ + '.NETTCPProxy')

trace_file = None


from lxml import etree

NAMESPACES = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://www.w3.org/2005/08/addressing",
    "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
    "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
    "da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}


def elem_get_text(elem):
    if elem is not None:
        text = elem.text
        if text is not None:
            return text.strip()
    return ''


def elem_is_empty(elem):
    # no text, no children, then empty
    return len(elem) == 0 and elem_get_text(elem) == ''


class XMLHelper(object):
    """
    A class helps to extract data from xml.
    """

    def __init__(self, xml):
        self.xml = xml
        self.root = etree.fromstring(xml)
        self.nsmap = self.root.nsmap
        # root ns + common ns
        self.nsmap.update(NAMESPACES)

    def get_elem(self, xpath, as_text=False):
        elem = self.root.find(xpath, self.nsmap)
        return elem_get_text(elem) if as_text else elem

    def get_elem_text(self, xpath):
        return self.get_elem(xpath, as_text=True)

    def get_elem_list(self, xpath, as_text=False):
        print(self.nsmap)
        elems = self.root.findall(xpath, self.nsmap)
        return [elem.text.strip() for elem in elems] if as_text else elems

    def is_elem_empty(self, xpath):
        """
        A empty element has no text and children

        e.g.: <s:Body></s:Body>
        """
        elem = self.root.find(xpath, self.nsmap)
        return elem_is_empty(elem)

def print_data(msg, data):
    if log.isEnabledFor(logging.DEBUG):
        print(msg, file=sys.stderr)
        if print_hexdump:
            print_hexdump(data, colored=True, file=sys.stderr)
        else:
            print(data, file=sys.stderr)

def print_xml(xml, sn=0, mode='w+'):
    # parse to validate
    root = etree.fromstring(xml)
    # print('######################XML HEAD##########################')
    # xml2 = etree.tostring(root, pretty_print=True)
    # print(xml2)
    # print('######################XML TAIL##########################')
    with open('/vagrant/%s.xml' % sn, mode) as f:
        f.write(xml + '\n\n\n')

request_index = 0

class NETTCPProxy(SocketServer.BaseRequestHandler):
    negoiate = True
    server_name = None

    def log_data(self, direction, data):
        if trace_file is None:
            return

        args = self.client_address + (direction, binascii.b2a_hex(data).decode())
        trace_file.write('{}\t{}:{}\t{}\t{}\n'.format(datetime.today(), *args))
        trace_file.flush()

    def handle(self):
        request_stream = SocketStream(self.request)
        self.stream = request_stream

        while True:
            obj = Record.parse_stream(self.stream)

            # log.debug('Client record: %s', obj)

            # data = obj.to_bytes()

            # self.log_data('c>s', data)

            # print_data('Got Data from client:', data)

            # self.stream.write(data)

            if obj.code == KnownEncodingRecord.code:
                # if self.negotiate:
                #     upgr = UpgradeRequestRecord(UpgradeProtocolLength=21,
                #                                 UpgradeProtocol='application/negotiate').to_bytes()
                #    s.sendall(upgr)
                #     resp = Record.parse_stream(SocketStream(s))
                #     assert resp.code == UpgradeResponseRecord.code, resp
                    # self.stream = GSSAPIStream(self.stream, self.server_name)
                # start receive thread
                # t.start()
                pass
            elif obj.code == UpgradeRequestRecord.code:
                upgr = UpgradeResponseRecord().to_bytes()
                request_stream.write(upgr)

                self.stream = GENSECStream(request_stream)
                self.stream.negotiate_server()
                self.negotiated = True

                preamble_end = Record.parse_stream(self.stream)
                assert preamble_end.code == PreambleEndRecord.code, preamble_end

                preamble_ack = PreambleAckRecord().to_bytes()
                self.stream.write(preamble_ack)
            elif obj.code == SizedEnvelopedMessageRecord.code:

                xml = obj.payload_to_xml()

                global request_index

                print_xml(xml, request_index, mode='w+')

                xmlhelper = XMLHelper(xml)

                # could be LDAP attrs or
                # synthetic attrs with namespace prefix
                AttributeType_List = xmlhelper.get_elem_list(
                    './/s:Body/da:BaseObjectSearchRequest/da:AttributeType',
                    as_text=True)

                context = {
                    'MessageID': xmlhelper.get_elem_text('.//a:MessageID'),
                    'objectReferenceProperty': xmlhelper.get_elem_text('.//ad:objectReferenceProperty'),
                    'Action': xmlhelper.get_elem_text('.//a:Action'),
                    'To': xmlhelper.get_elem_text('.//a:To'),
                    'AttributeType_List': AttributeType_List,
                }

                ack_xml = None

                if context['Action'] == 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get':
                    if sambautils.is_rootDSE(context['objectReferenceProperty']):
                        # search rootDSE
                        if not AttributeType_List:  # search all
                            ack_xml = sambautils.render_root_dse_xml(**context)
                        elif AttributeType_List == ['addata:msDS-PortLDAP']:
                            ack_xml = sambautils.render_msds_portldap(**context)
                    else:
                        # search object
                        ack_xml = sambautils.render_transfer_get(**context)

                assert ack_xml, 'I do not know how to answer'

                print_xml(ack_xml, request_index, mode='a')
                request_index += 1

                filename = '/vagrant/ack.xml'
                with open(filename, 'w+') as f:
                    f.write(ack_xml)

                from wcf.xml2records import XMLParser
                # import ipdb; ipdb.set_trace()
                # records = XMLParser.parse(ack_xml.encode('utf-8'))
                # print(records)
                from lib.converter import Converter
                converter = Converter(filename)
                converter.xml_to_mcnbfs(True)
                payload = converter.output

                # from wcf.records import dump_records
                # payload = dump_records(records)
                with open('/vagrant/payload.dat', 'wb+') as f:
                    f.write(payload)

                ack = SizedEnvelopedMessageRecord(
                    Payload=b'\x00' + payload,
                    Size=len(payload) + 1
                )
                _, ack2 = Record.parse(ack.to_bytes())
                assert ack2.Size == ack.Size
                assert ack2.Payload == ack.Payload
                self.stream.write(ack.to_bytes())

            elif obj.code == EndRecord.code:
                # TODO
                self.stream.close()


def main():
    import argparse
    global trace_file, TARGET_HOST, TARGET_PORT

    HOST, PORT = "localhost", 8090

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--trace_file', type=argparse.FileType('w'))
    parser.add_argument('-b', '--bind', default=HOST)
    parser.add_argument('-p', '--port', type=int, default=PORT)
    parser.add_argument('-n', '--negotiate', help='Negotiate with the given server name')
    parser.add_argument('TARGET_HOST')
    parser.add_argument('TARGET_PORT', type=int)

    args = parser.parse_args()

    TARGET_HOST = args.TARGET_HOST
    TARGET_PORT = args.TARGET_PORT

    trace_file = args.trace_file

    register_types()

    NETTCPProxy.negotiate = bool(args.negotiate)
    NETTCPProxy.server_name = args.negotiate

    if GSSAPIStream is None and NETTCPProxy.negotiate:
        log.error("GSSAPI not available, negotiation not possible. Try python2 with gssapi")
        sys.exit(1)

    server = SocketServer.TCPServer((args.bind, args.port), NETTCPProxy)

    server.serve_forever()

if __name__ == "__main__":
    main()
