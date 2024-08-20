import logging

log = logging.getLogger(__name__)

import sys
import uuid
import binascii
import argparse

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

from helperlib import print_hexdump

from nettcp import nmf
from nettcp.stream.socket import SocketStream
from nettcp.stream.gensec import GENSECStream

from wcf.xml2records import XMLParser
from wcf.records import dump_records

#from adws import sambautils
#from adws import xmlutils


import xmlschema
xs = xmlschema.XMLSchema('schemas/soap-envelope.xsd', build=False)

_ = xs.add_schema(open('schemas/ws-addr.xsd'))
_ = xs.add_schema(open('schemas/addressing.xsd'))

_ = xs.add_schema(open('schemas/transfer.xsd'))
_ = xs.add_schema(open('schemas/enumeration.xsd'))

_ = xs.add_schema(open('schemas/adlq.xsd'))
_ = xs.add_schema(open('schemas/ad.xsd'))
_ = xs.add_schema(open('schemas/ad-adhoc.xsd'))
_ = xs.add_schema(open('schemas/da-controls.xsd'))
_ = xs.add_schema(open('schemas/addata.xsd'))

_ = xs.add_schema(open('schemas/ad-fault.xsd'))
_ = xs.add_schema(open('schemas/ad-controls.xsd'))

xs.build()

def print_data(msg, data):
    if log.isEnabledFor(logging.DEBUG):
        print(msg, file=sys.stderr)
        print_hexdump(data, colored=True, file=sys.stderr)


class ADWSServer(SocketServer.BaseRequestHandler):

    def send_record(self, record):
        log.debug('<<<<Server record: %s' % record)
        self.stream.write(record.to_bytes())

    def handle(self):
        # this func is called in __init__ of base class
        log.info('start handle request')

        EnumerationContext_Dict = {}

        self.stream = SocketStream(self.request)
        negotiated = False
        request_index = 0

        # FIXME samdbhelper = sambautils.SamDBHelper()

        while True:

            log.debug('\n\nstart parsing stream...')
            obj = nmf.Record.parse_stream(self.stream)
            log.info('>>>>Client record: %s' % obj)

            if obj.code == nmf.KnownEncodingRecord.code:
                pass
            elif obj.code == nmf.UpgradeRequestRecord.code:
                self.send_record(nmf.UpgradeResponseRecord())
                if not negotiated:
                    log.info('negotiate started')
                    self.stream = GENSECStream(self.stream)
                    self.stream.negotiate_server()
                    negotiated = True
                    log.info('negotiate finished')
                else:
                    log.info('negotiate skipped')
            elif obj.code == nmf.PreambleEndRecord.code:
                log.info('preamble end')
                self.send_record(nmf.PreambleAckRecord())
            elif obj.code == nmf.SizedEnvelopedMessageRecord.code:
                from nettcp.dictionary import build_dictionary
                from wcf.records import Record, print_records

                from io import BytesIO, StringIO
                fp = BytesIO(obj.Payload)
                build_dictionary(fp, ('client', 'c>s'))
                records = Record.parse(fp)
                out = StringIO()
                print_records(records, fp=out)
                xml = out.getvalue()
                print(xml)

                decoded = xs.to_dict(xml)

                import server

                from samba.samdb import SamDB
                from samba.param import LoadParm
                from samba.auth import system_session
                lp = LoadParm()
                lp.load_default()
                samdb = SamDB(lp=lp, session_info=system_session())

                ack_xml = None
                if decoded['s:Header']['a:Action'][0]['$'] == 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get':
                    if 'da:IdentityManagementOperation' in decoded['s:Header']:
                        command = server.BaseGet(decoded, xs, samdb)
                    else:
                        command = server.Get(decoded, xs, samdb)
                    command.validate()
                    ack_xml = command.build_response()

                    print(ack_xml)

                assert ack_xml, 'I do not know how to answer'

                # FIXME xmlutils.print_xml(ack_xml, request_index, mode='a')
                request_index += 1

                #records = XMLParser.parse(ack_xml.encode('utf-8'))
                records = XMLParser.parse(ack_xml)
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

    def finish(self):
        self.stream.close()
        log.info('close stream and exit handle')


def main():
    import optparse
    import samba.getopt as options

    parser = optparse.OptionParser("main.py [options] <host>")
    sambaopts = options.SambaOptions(parser)
    parser.add_option_group(sambaopts)
    parser.add_option_group(options.VersionOptions(parser))

    credopts = options.CredentialsOptions(parser)
    parser.add_option_group(credopts)

    parser.add_option("-b", "--bind", type="str", dest="bind", default="localhost",
                  help="Specify timeout for DNS requests")
    parser.add_option("-p", "--port", type="int", dest="port", default=9389,
                  help="Specify timeout for DNS requests")
    opts, args = parser.parse_args()

    # lp = sambaopts.get_loadparm()
    # creds = credopts.get_credentials(lp)

    # realm = creds.get_realm()

    nmf.register_types()

    server = SocketServer.ForkingTCPServer((opts.bind, opts.port), ADWSServer)
    server.serve_forever()


if __name__ == "__main__":
    main()
