import lxml.etree as ET
from base64 import b64encode, b64decode
from samba.ndr import ndr_unpack
from samba.dcerpc import misc
from samba import dsdb
import uuid

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

class SimpleGet(AbstractFetch):

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
        base = self.xml['s:Header']['ad:objectReferenceProperty'][0]
        if base == ROOT_DSE_GUID:
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
        else:
            attr_names = []
            result = self.samdb.search(base=base, scope=ldb.SCOPE_BASE,
                                       attrs=['*', 'parentGUID'])

            msg = result[0]

            attrs = self.build_attr_list(msg, is_root_dse=False, attr_names=attr_names,
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

            resp_dict = self.response['s:Body']['addata:top'][0]

            for attr in attrs:
                resp_dict.update(attr.to_dict())

            # Get the objectClass correct
            body = self.response['s:Body']
            body['addata:' + oc] = body.pop('addata:top')

        output = self.schema.encode(self.response,
                                    path="s:Envelope",
                                    etree_element_class=ET.Element)
        return ET.tostring(output).decode()


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
                "da:BaseObjectSearchResponse": [
                    {
                        "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
                        "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                        "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
                        "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
                        "@xmlns:da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
                        "da:PartialAttribute": [
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

        controls = []
        if 'ad:controls' in base_search:
            ad_controls = base_search['ad:controls']['ad:control']
            for ctrl in ad_controls:
                controls.append(convert_controls(ctrl))

        print(controls)

        if 'da:AttributeType' in base_search:
            attr_names = [attr.split(':')[-1] for attr in base_search['da:AttributeType']]
            result = self.samdb.search(base=base, scope=ldb.SCOPE_BASE,
                                       attrs=attr_names, controls=controls)

            # ldb.MessageElement
            msg = result[0]

            attrs = self.build_attr_list(msg, is_root_dse=is_root_dse, attr_names=attr_names)

            resp_array = self.response['s:Body']['da:BaseObjectSearchResponse'][0]['da:PartialAttribute']

            for attr in attrs:
                resp_array.append(attr.to_dict())
        else:
            attr_names = []
            result = self.samdb.search(base=base, scope=ldb.SCOPE_BASE,
                                       attrs=['*', 'parentGUID'], controls=controls)
            msg = result[0]

            if is_root_dse:
                attrs = self.build_attr_list(msg, is_root_dse=is_root_dse, attr_names=attr_names,
                                             exclude=['dn', 'vendorName'])
            else:
                attrs = self.build_attr_list(msg, is_root_dse=is_root_dse, attr_names=attr_names,
                                             exclude=['dn', 'parentGUID'])

            if 'parentGUID' in msg:
                parent_guid = str(ndr_unpack(misc.GUID, msg['parentGUID'][0]))

            if is_root_dse:
                object_guid = ROOT_DSE_GUID
                dn = ''
                oc = 'top'
                rdn = ''
            else:
                object_guid = str(ndr_unpack(misc.GUID, msg['objectGUID'][0]))
                dn = str(msg['distinguishedName'][0])
                oc = str(msg['objectClass'][-1])
                rdn = get_rdn(msg['dn'])

            attrs.insert(0, SyntheticAttr('objectReferenceProperty', [object_guid]))
            # these 3 appear at last
            if not is_root_dse:
                if 'parentGUID' in msg:
                    attrs.append(SyntheticAttr('container-hierarchy-parent', [parent_guid]))
            else:
                attrs.append(SyntheticAttr('container-hierarchy-parent', [ROOT_DSE_GUID]))

            attrs.append(SyntheticAttr('relativeDistinguishedName', [rdn]))
            attrs.append(SyntheticAttr('distinguishedName', [dn]))

            resp_dict = {}

            for attr in attrs:
                resp_dict.update(attr.to_dict())
            resp_array = self.response['s:Body']['da:BaseObjectSearchResponse'][0]['da:PartialAttribute']
            resp_array.append({'addata:' + oc: [ resp_dict ] })

        if len(result.controls) > 0:
            resp_ctrls = convert_response_controls(result.controls)
            print(resp_ctrls)
            self.response['s:Body']['da:BaseObjectSearchResponse'][0]['ad:controls'] = resp_ctrls

        output = self.schema.encode(self.response,
                                    path="s:Envelope",
                                    etree_element_class=ET.Element)

        return ET.tostring(output).decode()


class Create(object):

    def __init__(self, xml, hostname, schema, samdb):
        self.xml = xml
        self.schema = schema
        self.samdb = samdb
        self.message_id = self.xml['s:Header']['a:MessageID'][0]

        self.response = {
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse",
                    }
                ],
                "a:RelatesTo": [
                    {
                        "$": self.message_id,
                    }
                ],
                "a:To": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://www.w3.org/2005/08/addressing/anonymous",
                    }
                ],
            },
            "s:Body": {
                "wst:ResourceCreated": [
                    {
                        "@xmlns:wst": "http://schemas.xmlsoap.org/ws/2004/09/transfer",
                        "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
                        "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                        "@xmlns:wsa": "http://www.w3.org/2005/08/addressing",
                        "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
                        "wsa:Address": [
                            "net.tcp://{}:9389/ActiveDirectoryWebServices/Windows/Resource".format(hostname)
                        ],
                        "wsa:ReferenceParameters": [
                            {
                                "ad:objectReferenceProperty": [
                                    ROOT_DSE_GUID
                                ],
                                "ad:instance": ["ldap:389"],
                            }
                        ],
                    }
                ]
            },
        }

    def execute(self):
        self.msg_dict = {}
        add_request = self.xml['s:Body']['da:AddRequest'][0]

        for attr in add_request['da:AttributeTypeAndValue']:
            # FIXME Handle case sensitivity
            if attr['da:AttributeType'] == 'ad:relativeDistinguishedName':
                self.rdn = attr['da:AttributeValue']['ad:value'][0]['$']

            elif attr['da:AttributeType'] == 'ad:container-hierarchy-parent':
                self.parent = attr['da:AttributeValue']['ad:value'][0]['$']
            else:
                name = attr['da:AttributeType'].split(':')[-1]
                val = [b64decode(v['$']) if v['@xsi:type'] == 'xsd:base64Binary' else v['$']
                       for v in attr['da:AttributeValue']['ad:value']]
                self.msg_dict.update({name: val})

        self.dn = "{},{}".format(self.rdn, self.parent)
        self.msg_dict['dn'] = self.dn
        print(self.msg_dict)

        self.samdb.add(self.msg_dict)

    def build_response(self):
        try:
            self.execute()
            msg = self.samdb.search(base=self.dn, scope=ldb.SCOPE_BASE,
                                    attrs=['objectGUID'])[0]
            object_guid = str(ndr_unpack(misc.GUID, msg['objectGUID'][0]))
            self.response['s:Body']['wst:ResourceCreated'][0]['wsa:ReferenceParameters'][0]['ad:objectReferenceProperty'] = [object_guid]
        except ldb.LdbError as e:
            # FIXME Replace with appropriate SOAP fault
            self.response = None
            raise e

        output = self.schema.encode(self.response,
                                    path="s:Envelope",
                                    etree_element_class=ET.Element)
        return ET.tostring(output).decode()

class Delete(object):

    def __init__(self, xml, schema, samdb):
        self.xml = xml
        self.schema = schema
        self.samdb = samdb
        self.message_id = self.xml['s:Header']['a:MessageID'][0]

        self.response = {
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse",
                    }
                ],
                "a:RelatesTo": [
                    {
                        "$": self.message_id,
                    }
                ],
                "a:To": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://www.w3.org/2005/08/addressing/anonymous",
                    }
                ],
            },
            "s:Body": None,
        }

    def execute(self):
        base = self.xml['s:Header']['ad:objectReferenceProperty'][0]
        controls = []

        if self.xml['s:Body']:
            ad_controls = self.xml['s:Body']['ad:controls'][0]['ad:control']
            for ctrl in ad_controls:
                controls.append(convert_controls(ctrl))

        if controls:
            self.samdb.delete(base, controls=controls)
        else:
            self.samdb.delete(base)

    def build_response(self):
        try:
            self.execute()
        except ldb.LdbError as e:
            # FIXME Replace with appropriate SOAP fault
            self.response = None
            raise e

        output = self.schema.encode(self.response,
                                    path="s:Envelope",
                                    etree_element_class=ET.Element)
        return ET.tostring(output).decode()


class Enumerate(AbstractFetch):

    def __init__(self, xml, dictionary, schema, samdb):
        self.xml = xml
        self.schema = schema
        self.samdb = samdb
        self.message_id = self.xml['s:Header']['a:MessageID'][0]
        self.enumeration_context = str(uuid.uuid4())

        self.dictionary = dictionary

        self.response = {
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse",
                    }
                ],
                "a:RelatesTo": [
                    {
                        "$": self.message_id,
                    }
                ],
            },
            "s:Body": {
                "wsen:EnumerateResponse": [
                    {
                        "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
                        "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                        "@xmlns:wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
                        "wsen:Expires": "9999-03-15T05:34:42.6778076Z", # FIXME Or not? Never expires
                        "wsen:EnumerationContext": self.enumeration_context,
                    }
                ]
            },
        }

    def validate(self):
        context = {'cookie': ''}
        context['query'] = self.xml['s:Body']['wsen:Enumerate'][0]['wsen:Filter']['adlq:LdapQuery']
        context['selection'] = self.xml['s:Body']['wsen:Enumerate'][0]['ad:Selection']
        self.dictionary[self.enumeration_context] = context

    def build_response(self):
        output = self.schema.encode(self.response,
                                    path="s:Envelope",
                                    etree_element_class=ET.Element)
        return ET.tostring(output).decode()

class EnumeratePull(AbstractFetch):

    def __init__(self, xml, dictionary, schema, samdb):
        self.xml = xml
        self.schema = schema
        self.samdb = samdb
        self.message_id = self.xml['s:Header']['a:MessageID'][0]
        self.enumeration_context = self.xml['s:Body']['wsen:Pull'][0]['wsen:EnumerationContext']

        self.dictionary = dictionary

        self.response = {
            "@xmlns:a": "http://www.w3.org/2005/08/addressing",
            "@xmlns:s": "http://www.w3.org/2003/05/soap-envelope",
            "s:Header": {
                "a:Action": [
                    {
                        "@s:mustUnderstand": True,
                        "$": "http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse",
                    }
                ],
                "a:RelatesTo": [
                    {
                        "$": self.message_id,
                    }
                ],
            },
            "s:Body": {
                "wsen:PullResponse": [
                    {
                        "@xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
                        "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                        "@xmlns:addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
                        "@xmlns:ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
                        "@xmlns:wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
                        "wsen:EnumerationContext": self.enumeration_context,
                        "wsen:Items": {
                            "addata:top": [

                            ]
                        },
                        "wsen:EndOfSequence": {
                            "@xmlns:wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
                        },
                    }
                ]
            },
        }


    def build_response(self):
        context = self.dictionary[self.enumeration_context]

        pull = self.xml['s:Body']['wsen:Pull'][0]
        max_elements = pull['wsen:MaxElements']

        controls = []
        if 'ad:controls' in pull:
            ad_controls = pull['ad:controls']['ad:control']
            for ctrl in ad_controls:
                convert = convert_controls(ctrl)

                if convert.startswith('paged_results:'):
                    raise Exception('Not allowed to use paging here!')

                controls.append(convert)

        end = True
        print(context)
        print(controls)

        attr_names = [attr.split(':')[-1] for attr in context['selection']['ad:SelectionProperty']]

        scope = SCOPE_ADLQ_TO_LDB[context['query']['adlq:Scope'].lower()]

        result = self.samdb.search(base=context['query']['adlq:BaseObject'],
                                   scope=scope,
                                   expression=context['query']['adlq:Filter'],
                                   attrs=attr_names + ['objectClass'],
                                   controls=controls + ['paged_results:1:%s%s' % (max_elements, context['cookie'])]
        )

        ctrls = [str(c) for c in result.controls if
                 str(c).startswith("paged_results")]
        spl = ctrls[0].rsplit(':', 3)
        if len(spl) == 3:
            new_cookie = ':' + spl[-1]
            context['cookie'] = new_cookie
            end = False

        objects = [
            (
                str(msg['objectClass'][-1]) if 'objectClass' in msg else None,
                self.build_attr_list(msg, attr_names=attr_names)
            )
            for msg in result.msgs
        ]

        resp_array = self.response['s:Body']['wsen:PullResponse'][0]['wsen:Items']['addata:top']

        for _, obj in objects:
            resp_dict = {}
            for attr in obj:
                resp_dict.update(attr.to_dict())

            resp_array.append(resp_dict)

        if not end:
            del self.response['s:Body']['wsen:PullResponse'][0]['wsen:EndOfSequence']
        else:
            del self.response['s:Body']['wsen:PullResponse'][0]['wsen:EnumerationContext']


        output = self.schema.encode(self.response,
                                    path="s:Envelope",
                                    etree_element_class=ET.Element)

        ################################
        #
        # BEGIN REWRITE OF OBJECTCLASSS
        #
        # THIS IS DONE HERE AS XMLSCHEMA DOES NOT PRESERVE ORDER
        #
        namespaces = {'addata': 'http://schemas.microsoft.com/2008/1/ActiveDirectory/Data'}
        addata_top = output.findall('.//addata:top', namespaces=namespaces)

        for i, o in enumerate(addata_top):
            oc = objects[i][0]
            if oc:
                o.tag = "{" + namespaces['addata'] + "}" + oc
        #
        # END REWRITE OF OBJECTCLASS
        ################################

        return ET.tostring(output).decode()

import ldb

def get_rdn(dn):
    rdn_name = dn.get_rdn_name()
    rdn_value = dn.get_rdn_value()
    if rdn_name and rdn_value:
        return '%s=%s' % (rdn_name, rdn_value)
    return ''

def handle_sd_flags(ctrl):
    from pyasn1.codec.ber.decoder import decode
    oid = ctrl['@type']
    crit = ctrl['@criticality']

    import asn1ctrl
    ctrl_bytes = b64decode(ctrl['ad:controlValue']['$'])

    record, _ = decode(ctrl_bytes, asn1Spec=asn1ctrl.SDFlagsRequestValue())
    return 'sd_flags:%s:%d' % (CRITICALITY_MAP[crit], record['flags'])

def handle_paged_results(ctrl):
    from pyasn1.codec.ber.decoder import decode
    oid = ctrl['@type']
    crit = ctrl['@criticality']

    import asn1ctrl
    ctrl_bytes = b64decode(ctrl['ad:controlValue']['$'])

    record, _ = decode(ctrl_bytes, asn1Spec=asn1ctrl.PagedResultsControlValue())

    cookie = ''
    if record['cookie']:
        cookie = ':' + record['cookie']

    return 'paged_results:%s:%s%s' % (CRITICALITY_MAP[crit], record['size'], cookie)

SIMPLE_CONTROLS_MAP = {
    '1.2.840.113556.1.4.805': 'tree_delete',
}

COMPLEX_CONTROLS_MAP = {
    '1.2.840.113556.1.4.801': handle_sd_flags,
    '1.2.840.113556.1.4.319': handle_paged_results,
}

CRITICALITY_MAP = {
    True: '1',
    False: '0',
}

def convert_controls(ctrl):
    oid = ctrl['@type']
    crit = ctrl['@criticality']
    if oid in SIMPLE_CONTROLS_MAP:
        return '{}:{}'.format(SIMPLE_CONTROLS_MAP[oid], CRITICALITY_MAP[crit])

    if oid in COMPLEX_CONTROLS_MAP:
        return COMPLEX_CONTROLS_MAP[oid](ctrl)

    raise Exception('Unhandled control: ' + oid)

def convert_response_controls(resp_ctrls):
    ad_control = []

    for ctrl in resp_ctrls:
        if str(ctrl).startswith('paged_results:'):
            from pyasn1.codec.ber.encoder import encode

            import asn1ctrl

            record = asn1ctrl.PagedResultsControlValue()

            spl = str(ctrl).rsplit(':', 3)
            if len(spl) == 3:
                record['cookie'] = b64decode(spl[-1])
            else:
                record['cookie'] = ''

            record['size'] = int(spl[1])

            bytes_output = encode(record)

            ad_control.append({
                '@type': ctrl.oid,
                '@criticality': ctrl.critical,
                'ad:controlValue': {
                    '@xsi:type': 'xsd:base64Binary',
                    '$': b64encode(bytes_output).decode()
                }

            })
        else:
            raise Exception('Unhandled control: ' + ctrl)

    return {'ad:control': ad_control}

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
    SchemaSyntax("1.2.840.113556.1.4.907", 'NTSecurityDescriptor', xsi_type='xsd:base64Binary'),
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
    'msDS-PortLDAP': ldb.SYNTAX_INTEGER,
    # vendorName is Samba-only - currently omitted from response
}

SYNTHETIC_ATTRS = {
    'objectReferenceProperty',
    'container-hierarchy-parent',
    'distinguishedName',
    'relativeDistinguishedName',
}

ROOT_DSE_GUID = '11111111-1111-1111-1111-111111111111'

# https://msdn.microsoft.com/en-us/library/dd340513.aspx
SCOPE_ADLQ_TO_LDB = {
    'base': ldb.SCOPE_BASE,
    'onelevel': ldb.SCOPE_ONELEVEL,
    'subtree': ldb.SCOPE_SUBTREE,
}

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

        self.vals = vals

    def to_dict(self):
        return {"ad:" + self.attr: [
            {
                "ad:value": [
                    {"@xsi:type": self.xsi_type, "$": str(val)} for val in self.vals
                ]
            }
        ]}
