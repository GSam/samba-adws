import uuid
import lxml.etree as ET

from wcf.xml2records import XMLParser
from wcf.records import print_records, dump_records, Record

from io import BytesIO, StringIO

import socket
from nettcp.stream.socket import SocketStream
from nettcp.stream.nmf import NMFStream

from wcf.datatypes import MultiByteInt31, Utf8String
from wcf.dictionary import dictionary

from abc import ABC

old_dictionary = dictionary.copy()

class Service(object):

    def __init__(self, service, fqdn, host, ipaddress, creds):

        self.uri = 'net.tcp://{}:9389/ActiveDirectoryWebServices/'.format(fqdn) + service

        if ipaddress:
            s = socket.create_connection((ipaddress, 9389))
        else:
            s = socket.create_connection((host, 9389))

        socket_stream = SocketStream(s)

        self.stream = NMFStream(socket_stream, self.uri, host, creds)
        self.stream.preamble()

        self.idx = 1
        self.dictionary_cache = {}

    def update_dictionary(self, fp):
        size = MultiByteInt31.parse(fp).value
        print("Dictionary table: {} bytes".format(size))
        table_data = fp.read(size)
        table = BytesIO(table_data)

        while table.tell() < size:
            string = Utf8String.parse(table)
            assert self.idx not in dictionary_cache
            self.dictionary_cache[idx] = string.value
            self.idx += 2

        if len(self.dictionary_cache) > 0:
            dictionary.clear()
            dictionary.update(old_dictionary)
            dictionary.update(self.dictionary_cache)

        for idx, value in self.dictionary_cache.items():
            print('{}: {}'.format(idx, value))
        return self.dictionary_cache

    def reset_dictionary(self):
        if len(self.dictionary_cache) > 0:
            dictionary.clear()
            dictionary.update(old_dictionary)

    def close(self):
        self.stream.close()


class Transfer(ABC):

    def to_xml(self):
        output = self.schema.encode(self.xml,
                                   path="s:Envelope",
                                   etree_element_class=ET.Element)
        return ET.tostring(output).decode()

    def send(self):
        stream = self.service.stream

        x = XMLParser.parse(self.to_xml())
        print_records(x)

        stream.write(b'\x00' + dump_records(x))

        payload = stream.read()
        fp = BytesIO(payload)

        self.service.update_dictionary(fp)

        out = StringIO()
        records = Record.parse(fp)
        print_records(records, fp=out)

        self.service.reset_dictionary()
        return out.getvalue()


class RootDSEGet(Transfer):

    def __init__(self, schema, service_map):
        self.service = service_map['Windows/Resource']
        self.schema = schema
        self.xml = {
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
            "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get",
                    }
                ],
                "ad:instance": ["ldap:389"],
                "ad:objectReferenceProperty": ["11111111-1111-1111-1111-111111111111"],
                "a:MessageID": ["urn:uuid:" + str(uuid.uuid4())],
                "a:ReplyTo": [{"a:Address": "http://www.w3.org/2005/08/addressing/anonymous"}],
                "a:To": [
                    {
                        "@s:mustUnderstand": True,
                        "$": self.service.uri
                    }
                ],
            },
            "s:Body": None,
        }



class RootDSEPortLDAP(Transfer):

    def __init__(self, schema, service_map):
        self.service = service_map['Windows/Resource']
        self.schema = schema
        self.xml = {
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
            "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "@xmlns:da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get",
                    }
                ],
                "ad:instance": ["ldap:389"],
                "ad:objectReferenceProperty": ["11111111-1111-1111-1111-111111111111"],
                "da:IdentityManagementOperation": [
                    {
                        "@xmlns:i": "http://www.w3.org/2001/XMLSchema-instance",
                        "@s:mustUnderstand": True,
                    }
                ],
                "a:MessageID": ["urn:uuid:" + str(uuid.uuid4())],
                "a:ReplyTo": [{"a:Address": "http://www.w3.org/2005/08/addressing/anonymous"}],
                "a:To": [
                    {
                        "@s:mustUnderstand": True,
                        "$": self.service.uri
                    }
                ],
            },
            "s:Body": {
                "da:BaseObjectSearchRequest": [
                    {
                        "@Dialect": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1",
                        "da:AttributeType": ["addata:msDS-PortLDAP"],
                    }
                ]
            },
        }


class Get(Transfer):

    def __init__(self, iden, schema, service_map):
        self.service = service_map['Windows/Resource']
        self.schema = schema
        self.xml = {
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
            "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "@xmlns:da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get",
                    }
                ],
                "ad:instance": ["ldap:389"],
                "ad:objectReferenceProperty": [
                    iden
                ],
                "da:IdentityManagementOperation": [
                    {
                        "@xmlns:i": "http://www.w3.org/2001/XMLSchema-instance",
                        "@s:mustUnderstand": True,
                    }
                ],
                "a:MessageID": ["urn:uuid:" + str(uuid.uuid4())],
                "a:ReplyTo": [{"a:Address": "http://www.w3.org/2005/08/addressing/anonymous"}],
                "a:To": [
                    {
                        "@s:mustUnderstand": True,
                        "$": self.service.uri
                    }
                ],
            },
            "s:Body": {
                "da:BaseObjectSearchRequest": [
                    {
                        "@Dialect": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1",
                    }
                ]
            },
        }


class SimpleGet(Get):

    def __init__(self, iden, schema, service_map):
        super(SimpleGet, self).__init__(iden, schema, service_map)

        self.xml['s:Body'] = None
        del self.xml['s:Header']["da:IdentityManagementOperation"]


class Create(Transfer):

    def __init__(self, target, object_class, schema, service_map):
        self.service = service_map['Windows/ResourceFactory']
        self.schema = schema
        self.rdn, self.parent = target.split(',', 1)
        self.xml = {
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
            "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "@xmlns:da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
                    }
                ],
                "ad:instance": ["ldap:389"],
                "da:IdentityManagementOperation": [
                    {
                        "@xmlns:i": "http://www.w3.org/2001/XMLSchema-instance",
                        "@s:mustUnderstand": True,
                    }
                ],
                "a:MessageID": ["urn:uuid:" + str(uuid.uuid4())],
                "a:ReplyTo": [{"a:Address": "http://www.w3.org/2005/08/addressing/anonymous"}],
                "a:To": [
                    {
                        "@s:mustUnderstand": True,
                        "$": self.service.uri
                    }
                ],
            },
            "s:Body": {
                "da:AddRequest": [
                    {
                        "@Dialect": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1",
                        "da:AttributeTypeAndValue": [
                            {
                                "da:AttributeType": "addata:objectClass",
                                "da:AttributeValue": {
                                    "ad:value": [{"@xsi:type": "xsd:string", "$": object_class}]
                                },
                            },
                            {
                                "da:AttributeType": "ad:relativeDistinguishedName",
                                "da:AttributeValue": {
                                    "ad:value": [
                                        {"@xsi:type": "xsd:string", "$": self.rdn}
                                    ]
                                },
                            },
                            {
                                "da:AttributeType": "ad:container-hierarchy-parent",
                                "da:AttributeValue": {
                                    "ad:value": [
                                        {
                                            "@xsi:type": "xsd:string",
                                            "$": self.parent,
                                        }
                                    ]
                                },
                            },
                        ],
                        "ad:controls": {
                            "ad:control": [
                                {
                                    "@type": "1.2.840.113556.1.4.801",
                                    "@criticality": True,
                                    "ad:controlValue": {
                                        "@xsi:type": "xsd:base64Binary",
                                        "$": "MIQAAAADAgEE",
                                    },
                                }
                            ]
                        },
                    }
                ]
            },
        }


class Delete(Transfer):

    def __init__(self, iden,  schema, service_map):
        self.service = service_map['Windows/Resource']
        self.schema = schema

        self.xml = {
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
            "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
                    }
                ],
                "ad:instance": ["ldap:389"],
                "ad:objectReferenceProperty": [
                    iden
                ],
                "a:MessageID": ["urn:uuid:" + str(uuid.uuid4())],
                "a:ReplyTo": [{"a:Address": "http://www.w3.org/2005/08/addressing/anonymous"}],
                "a:To": [
                    {
                        "@s:mustUnderstand": True,
                        "$": self.service.uri
                    }
                ],
            },
            "s:Body": None,
        }
