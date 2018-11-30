#!/usr/bin/env python2
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import

import sys
import uuid
import binascii
import argparse

import logging
from logging.config import dictConfig
try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

from helperlib import print_hexdump

from nettcp import nmf
from nettcp.stream.socket import SocketStream
from nettcp.stream.gssapi import GSSAPIStream, GENSECStream

from adws import sambautils
from adws import xmlutils

LOG_FORMAT = ('%(levelname)s %(asctime)s pid:%(process)d '
          '%(name)s %(pathname)s #%(lineno)d: %(message)s')

LOG_CONFIG = {
    'version': 1,
    'formatters': {
        'verbose': {'format': LOG_FORMAT},
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'level': logging.DEBUG,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': logging.DEBUG,
    },
    'loggers': {
        'wcf': {
            'level': logging.WARN,
        },
        'nettcp': {
            'level': logging.WARN,
        },
    },
}

dictConfig(LOG_CONFIG)
LOG = logging.getLogger(__name__)


def print_data(msg, data):
    if LOG.isEnabledFor(logging.DEBUG):
        print(msg, file=sys.stderr)
        print_hexdump(data, colored=True, file=sys.stderr)


class NETTCPProxy(SocketServer.BaseRequestHandler):

    def send_record(self, record):
        print('<<<<Server record: %s' % record)
        self.stream.write(record.to_bytes())

    def handle(self):
        # this func is called in __init__ of base class
        print('\n\na new handler instance created, handle start')

        EnumerationContext_Dict = {}

        self.stream = SocketStream(self.request)
        negotiated = False
        request_index = 0

        samdbhelper = sambautils.SamDBHelper()

        while True:

            print('\n\nparsing stream...')
            obj = nmf.Record.parse_stream(self.stream)
            print('>>>>Client record: %s' % obj)

            # data = obj.to_bytes()

            # self.log_data('c>s', data)

            # print_data('Got Data from client:', data)

            # self.stream.write(data)

            if obj.code == nmf.KnownEncodingRecord.code:
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
            elif obj.code == nmf.UpgradeRequestRecord.code:
                self.send_record(nmf.UpgradeResponseRecord())
                if not negotiated:
                    self.stream = GENSECStream(self.stream)
                    self.stream.negotiate_server()
                    negotiated = True
                    print('negotiate finished')
                else:
                    print('negotiate skipped')
            elif obj.code == nmf.PreambleEndRecord.code:
                self.send_record(nmf.PreambleAckRecord())
            elif obj.code == nmf.SizedEnvelopedMessageRecord.code:

                xml = obj.payload_to_xml()

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
                ack = nmf.SizedEnvelopedMessageRecord(
                    Payload=b'\x00' + payload,
                    Size=size
                )
                _, ack2 = nmf.Record.parse(ack.to_bytes())
                assert ack2.Size == ack.Size
                assert ack2.Payload == ack.Payload
                self.send_record(ack)
            elif obj.code == nmf.EndRecord.code:
                break

        print('exit handle')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--bind', default='localhost')
    parser.add_argument('-p', '--port', type=int, default=9389)
    args = parser.parse_args()

    nmf.register_types()

    server = SocketServer.ForkingTCPServer((args.bind, args.port), NETTCPProxy)
    server.serve_forever()


if __name__ == "__main__":
    main()
