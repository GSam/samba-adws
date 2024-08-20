import lxml.etree as ET
from base64 import b64encode
from samba.ndr import ndr_unpack
from samba.dcerpc import misc
from samba import dsdb

class SchemaSyntax(object):

    def __init__(self, oid, ldap_syntax, xsi_type='xsd:string'):
        self.oid = oid
        self.ldap_syntax = ldap_syntax
        self.xsi_type = xsi_type

class AbstractFetch(object):
    def get_attr_schema_syntax(self, attr, is_root_dse=False):
        if is_root_dse:
            oid = ROOT_DSE_ATTRS.get(attr)
        else:
            oid = self.samdb.get_syntax_oid_from_lDAPDisplayName(attr)
        return oid and OID_SCHEMA_SYNTAX_DICT.get(oid) or None

    def build_attr_list(self, msg, is_root_dse=False, attr_names=[], exclude=[]):
        if not attr_names:
            attr_names = list(msg.keys())

        attrs = []
        for attr_name in attr_names:
            if attr_name in exclude:
                continue

            attr_obj = None
            vals = msg.get(attr_name, None)
            if vals is not None:
                if attr_name in SYNTHETIC_ATTRS:
                    attr_obj = SyntheticAttr(attr_name, vals)
                else:
                    syntax = self.get_attr_schema_syntax(
                        attr_name, is_root_dse=is_root_dse)
                    assert syntax, 'syntax not found for %s' % attr_name
                    if syntax:
                        attr_obj = LdapAttr(
                            attr_name, vals,
                            syntax.ldap_syntax, syntax.xsi_type)
            else:
                if attr_name == 'relativeDistinguishedName':
                    attr_obj = SyntheticAttr(attr_name, [get_rdn(msg['dn'])])
            if attr_obj:
                attrs.append(attr_obj)

        return attrs

class Get(AbstractFetch):

    def __init__(self, xml, schema, samdb):
        self.xml = xml
        self.schema = schema
        self.samdb = samdb
        self.message_id = self.xml['s:Header']['a:MessageID'][0]

        self.response = {
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse",
                    }
                ],
                "a:RelatesTo": [
                    {
                        "$": self.message_id,
                    }
                ],
            },
            "s:Body": {
                "addata:top": [
                    {
                        "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
                        "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
                        "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                        "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
                    }
                ]
            },
        }

    def validate(self):
        return True

    def build_response(self):
        result = self.samdb.search(base='', scope=ldb.SCOPE_BASE)
        # ldb.MessageElement
        msg = result[0]

        attrs = self.build_attr_list(msg, is_root_dse=True, exclude=['dn', 'vendorName'])

        attrs.insert(0, SyntheticAttr('objectReferenceProperty', [ROOT_DSE_GUID]))
        # these 3 appear at last
        attrs.append(SyntheticAttr('container-hierarchy-parent', [ROOT_DSE_GUID]))
        attrs.append(SyntheticAttr('relativeDistinguishedName', ['']))
        attrs.append(SyntheticAttr('distinguishedName', ['']))

        resp_dict = self.response['s:Body']['addata:top'][0]

        for attr in attrs:
            resp_dict.update(attr.to_dict())

        if False:
            body = self.response['s:Body']
            body['addata:' + oc] = body.pop('addata:top')

        output = self.schema.encode(self.response,
                                    path="s:Envelope",
                                    etree_element_class=ET.Element)
        return ET.tostring(output).decode()


class BaseGet(AbstractFetch):

    def __init__(self, xml, schema, samdb):
        self.xml = xml
        self.schema = schema
        self.samdb = samdb
        self.message_id = self.xml['s:Header']['a:MessageID'][0]

        self.response = {
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse",
                    }
                ],
                "a:RelatesTo": [
                    {
                        "$": self.message_id,
                    }
                ],
            },
            "s:Body": {
                "da:BaseObjectSearchResponse": [
                    {
                        "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
                        "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                        "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
                        "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
                        "@xmlns:da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
                        "da:PartialAttribute": [
                        #    {
                        #        "addata:msDS-PortLDAP": [
                        #            {
                        #                "@LdapSyntax": "Integer",
                        #                "ad:value": [{"@xsi:type": "xsd:string", "$": "389"}],
                        #            }
                        #        ],
                        #    }
                        ],
                    }
                ]
            },
        }

    def validate(self):
        return True

    def build_response(self):
        base = self.xml['s:Header']['ad:objectReferenceProperty'][0]
        is_root_dse = False

        if base == ROOT_DSE_GUID:
            base = ''
            is_root_dse = True

        base_search = self.xml['s:Body']['da:BaseObjectSearchRequest'][0]
        if 'da:AttributeType' in base_search:
            attr_names = [attr.split(':')[-1] for attr in ['da:AttributeType']]
            result = self.samdb.search(base=base, scope=ldb.SCOPE_BASE, attrs=attr_names)

            # ldb.MessageElement
            msg = result[0]

            attrs = self.build_attr_list(msg, is_root_dse=is_root_dse, attr_names=attr_names)

            resp_array = self.response['s:Body']['da:BaseObjectSearchResponse'][0]['da:PartialAttribute']

            for attr in attrs:
                resp_array.append(attr.to_dict())
        else:
            attr_names = []
            result = self.samdb.search(base=base, scope=ldb.SCOPE_BASE, attrs=['*', 'parentGUID'])
            msg = result[0]

            attrs = self.build_attr_list(msg, is_root_dse=is_root_dse, attr_names=attr_names,
                                         exclude=['dn', 'parentGUID'])

            object_guid = str(ndr_unpack(misc.GUID, msg['objectGUID'][0]))
            if 'parentGUID' in msg:
                parent_guid = str(ndr_unpack(misc.GUID, msg['parentGUID'][0]))

            dn = str(msg['distinguishedName'][0])
            oc = str(msg['objectClass'][-1])

            attrs.insert(0, SyntheticAttr('objectReferenceProperty', [object_guid]))
            # these 3 appear at last
            if 'parentGUID' in msg:
                attrs.append(SyntheticAttr('container-hierarchy-parent', [parent_guid]))

            attrs.append(SyntheticAttr('relativeDistinguishedName', [get_rdn(msg['dn'])]))
            attrs.append(SyntheticAttr('distinguishedName', [dn]))

            resp_dict = {}

            for attr in attrs:
                resp_dict.update(attr.to_dict())
            resp_array = self.response['s:Body']['da:BaseObjectSearchResponse'][0]['da:PartialAttribute']
            resp_array.append({'addata:' + oc: [ resp_dict ] })

        output = self.schema.encode(self.response,
                                    path="s:Envelope",
                                    etree_element_class=ET.Element)
        return ET.tostring(output).decode()

import ldb

def get_rdn(dn):
    rdn_name = dn.get_rdn_name()
    rdn_value = dn.get_rdn_value()
    if rdn_name and rdn_value:
        return '%s=%s' % (rdn_name, rdn_value)
    return ''

# MS-ADDM 2.3.4 Syntax Mapping
SCHEMA_SYNTAX_LIST = [
    SchemaSyntax(ldb.SYNTAX_INTEGER, 'Integer'),
    SchemaSyntax(ldb.SYNTAX_LARGE_INTEGER, 'LargeInteger'),
    SchemaSyntax(ldb.SYNTAX_BOOLEAN, 'Boolean'),
    SchemaSyntax(ldb.SYNTAX_DIRECTORY_STRING, 'UnicodeString'),
    SchemaSyntax(ldb.SYNTAX_OCTET_STRING, 'OctetString', xsi_type='xsd:base64Binary'),
    SchemaSyntax(ldb.SYNTAX_DN, 'DSDNString'),
    SchemaSyntax(ldb.SYNTAX_UTC_TIME, 'UTCTimeString'),
    SchemaSyntax(ldb.SYNTAX_GENERALIZED_TIME, 'GeneralizedTimeString'),
    SchemaSyntax(ldb.SYNTAX_OBJECT_IDENTIFIER, 'ObjectIdentifier'),
    SchemaSyntax(dsdb.DSDB_SYNTAX_BINARY_DN, 'DNBinary'),
]

OID_SCHEMA_SYNTAX_DICT = {obj.oid: obj for obj in SCHEMA_SYNTAX_LIST}

# MS-ADDM 5 Appendix A <4>
ROOT_DSE_ATTRS = {
    'configurationNamingContext': ldb.SYNTAX_DN,
    'currentTime': ldb.SYNTAX_GENERALIZED_TIME,
    'defaultNamingContext': ldb.SYNTAX_DN,
    'dnsHostName': ldb.SYNTAX_DIRECTORY_STRING,
    'domainControllerFunctionality': ldb.SYNTAX_INTEGER,
    'domainFunctionality': ldb.SYNTAX_INTEGER,
    'dsServiceName': ldb.SYNTAX_DN,
    'forestFunctionality': ldb.SYNTAX_INTEGER,
    'highestCommittedUSN': ldb.SYNTAX_LARGE_INTEGER,
    'isGlobalCatalogReady': ldb.SYNTAX_BOOLEAN,
    'isSynchronized': ldb.SYNTAX_BOOLEAN,
    'ldapServiceName': ldb.SYNTAX_DIRECTORY_STRING,
    'namingContexts': ldb.SYNTAX_DN,
    'rootDomainNamingContext': ldb.SYNTAX_DN,
    'schemaNamingContext': ldb.SYNTAX_DN,
    'serverName': ldb.SYNTAX_DN,
    'subschemaSubentry': ldb.SYNTAX_DN,
    'supportedCapabilities': ldb.SYNTAX_OBJECT_IDENTIFIER,
    'supportedControl': ldb.SYNTAX_OBJECT_IDENTIFIER,
    'supportedLDAPVersion': ldb.SYNTAX_INTEGER,
    # 'verdorName': 'not exist',
    'msDS-PortLDAP': ldb.SYNTAX_INTEGER,
}

SYNTHETIC_ATTRS = {
    'objectReferenceProperty',
    'container-hierarchy-parent',
    'distinguishedName',
    'relativeDistinguishedName',
}

ROOT_DSE_GUID = '11111111-1111-1111-1111-111111111111'

class LdapAttr(object):

    def __init__(self, attr, vals, ldap_syntax, xsi_type='xsd:string'):
        self.attr = attr  # sAMAccountName
        self.ldap_syntax = ldap_syntax
        assert ':' in xsi_type
        self.xsi_type = xsi_type

        if self.xsi_type == 'xsd:base64Binary':
            vals = [b64encode(val).decode('utf-8') for val in vals]
            #vals = [b64encode(val) for val in vals]
        self.vals = vals


    def to_dict(self):
        return {"addata:" + self.attr: [
            {
                "@LdapSyntax": self.ldap_syntax,
                "ad:value": [
                    {"@xsi:type": self.xsi_type, "$": str(val)} for val in self.vals
                ]
            }
        ]}

class SyntheticAttr(object):

    def __init__(self, attr, vals, xsi_type='xsd:string'):
        assert attr in SYNTHETIC_ATTRS
        self.attr = attr
        self.xsi_type = xsi_type

        # FIXME: could be other iterable
        if not isinstance(vals, list):
            vals = [vals]
        #if self.xsi_type == 'xsd:base64Binary':
        #    vals = [b64encode(val) for val in vals]
        self.vals = vals

    def to_dict(self):
        return {"ad:" + self.attr: [
            {
                "ad:value": [
                    {"@xsi:type": self.xsi_type, "$": str(val)} for val in self.vals
                ]
            }
        ]}
