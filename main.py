#!/usr/bin/env python2
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import
from datetime import datetime
from io import BytesIO, StringIO

import uuid
import socket
import logging
import sys
import binascii
import threading
import warnings

from nettcp.nmf import Record as NMFRecord, register_types

from adws import sambautils
from adws import xmlutils

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


def print_data(msg, data):
    if log.isEnabledFor(logging.DEBUG):
        print(msg, file=sys.stderr)
        if print_hexdump:
            print_hexdump(data, colored=True, file=sys.stderr)
        else:
            print(data, file=sys.stderr)

request_index = 0

class NETTCPProxy(SocketServer.BaseRequestHandler):
    server_name = None

    def log_data(self, direction, data):
        if trace_file is None:
            return

        args = self.client_address + (direction, binascii.b2a_hex(data).decode())
        trace_file.write('{}\t{}:{}\t{}\t{}\n'.format(datetime.today(), *args))
        trace_file.flush()

    def send_record(self, record):
        print('<<<<Server record: %s' % record)
        self.stream.write(record.to_bytes())

    def handle(self):
        # this func is called in __init__ of base class
        print('\n\na new handler instance created, handle start')

        EnumerationContext_Dict = {}

        self.stream = SocketStream(self.request)

        samdbhelper = sambautils.SamDBHelper()

        while self.stream:
            print('while loop start...')

            obj = Record.parse_stream(self.stream)
            print('\n\n>>>>Client record: %s' % obj)

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
                self.send_record(UpgradeResponseRecord())

                self.stream = GENSECStream(self.stream)
                self.stream.negotiate_server()
            elif obj.code == PreambleEndRecord.code:
                self.send_record(PreambleAckRecord())
            elif obj.code == SizedEnvelopedMessageRecord.code:

                xml = obj.payload_to_xml()

                global request_index

                xmlutils.print_xml(xml, request_index, mode='w+')

                xmlhelper = xmlutils.XMLHelper(xml)

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
                            ack_xml = samdbhelper.render_root_dse_xml(**context)
                        elif AttributeType_List == ['addata:msDS-PortLDAP']:
                            ack_xml = samdbhelper.render_msds_portldap(**context)
                    else:
                        # search object
                        ack_xml = samdbhelper.render_transfer_get(**context)
                elif context['Action'] == 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate':
                    enumeration_context = {}
                    ldapquery_elem = xmlhelper.get_elem('.//adlq:LdapQuery')
                    adlq_len = len(xmlutils.NAMESPACES['adlq']) + 2
                    # tag: '{http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery}Filter'
                    enumeration_context['LdapQuery'] = {
                        child.tag[adlq_len:]: child.text.strip()
                        for child in ldapquery_elem
                    }
                    enumeration_context['SelectionProperty_List'] = xmlhelper.get_elem_list(
                        './/ad:SelectionProperty', as_text=True)

                    EnumerationContext = str(uuid.uuid1())
                    EnumerationContext_Dict[EnumerationContext] = enumeration_context

                    context['EnumerationContext'] = EnumerationContext
                    ack_xml = samdbhelper.render_enumerate(**context)

                elif context['Action'] == 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull':
                    context['MaxElements'] = xmlhelper.get_elem_text('.//wsen:MaxElements')
                    EnumerationContext = xmlhelper.get_elem_text('.//wsen:EnumerationContext')

                    enumeration_context = EnumerationContext_Dict[EnumerationContext]
                    context['EnumerationContext'] = enumeration_context

                    context.update(enumeration_context)

                    ack_xml = samdbhelper.render_pull(**context)

                assert ack_xml, 'I do not know how to answer'

                xmlutils.print_xml(ack_xml, request_index, mode='a')
                request_index += 1

                from wcf.xml2records import XMLParser
                records = XMLParser.parse(ack_xml.encode('utf-8'))
                from wcf.records import dump_records
                payload = dump_records(records)

                size = len(payload) + 1
                print('output payload size: %d' % size)
                ack = SizedEnvelopedMessageRecord(
                    Payload=b'\x00' + payload,
                    Size=size
                )
                _, ack2 = Record.parse(ack.to_bytes())
                assert ack2.Size == ack.Size
                assert ack2.Payload == ack.Payload
                self.send_record(ack)
            elif obj.code == EndRecord.code:
                break

        print('exit handle')


def main():
    import argparse
    global trace_file

    HOST, PORT = "localhost", 8090

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--trace_file', type=argparse.FileType('w'))
    parser.add_argument('-b', '--bind', default=HOST)
    parser.add_argument('-p', '--port', type=int, default=PORT)
    parser.add_argument('-n', '--negotiate', help='Negotiate with the given server name')
    args = parser.parse_args()

    trace_file = args.trace_file

    register_types()

    NETTCPProxy.negotiate = bool(args.negotiate)
    NETTCPProxy.server_name = args.negotiate

    if GSSAPIStream is None and NETTCPProxy.negotiate:
        log.error("GSSAPI not available, negotiation not possible. Try python2 with gssapi")
        sys.exit(1)

    server = SocketServer.ForkingTCPServer((args.bind, args.port), NETTCPProxy)

    server.serve_forever()

if __name__ == "__main__":
    main()
