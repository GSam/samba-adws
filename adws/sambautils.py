#!/usr/bin/env python
from __future__ import print_function, absolute_import

from base64 import b64encode

import ldb
import samba
from samba.samdb import SamDB
from samba.param import LoadParm
from samba.auth import system_session
from samba import dsdb

from os.path import abspath, dirname, join

import jinja2
from jinja2 import Environment, FileSystemLoader, select_autoescape

HERE = dirname(abspath(__file__))
TEMPLATES = join(HERE, 'templates')

ENV = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=select_autoescape(['xml']),
)


# https://msdn.microsoft.com/en-us/library/dd340513.aspx
SCOPE_ADLQ_TO_LDB = {
    'base': ldb.SCOPE_BASE,
    'onelevel': ldb.SCOPE_ONELEVEL,
    'subtree': ldb.SCOPE_SUBTREE,
}


def render_template(template_name, **kwargs):
    template = ENV.get_template(template_name)
    return template.render(**kwargs)


class SchemaSyntax(object):

    def __init__(self, oid, ldap_syntax, xsi_type='xsd:string'):
        self.oid = oid
        self.ldap_syntax = ldap_syntax
        self.xsi_type = xsi_type

    def render(self):
        return 'xml'

ROOT_DSE_GUID = '11111111-1111-1111-1111-111111111111'


def is_rootDSE(guid):
    return guid.strip() == ROOT_DSE_GUID


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
]

OID_SCHEMA_SYNTAX_DICT = {obj.oid: obj for obj in SCHEMA_SYNTAX_LIST}

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
}

LDAP_ATTR_TEMPLATE = jinja2.Template("""
<addata:{{obj.attr}} LdapSyntax="{{obj.ldap_syntax}}">
   {%- for val in obj.vals %}
   <ad:value xsi:type="{{obj.xsi_type}}">{{val}}</ad:value>
   {%- endfor %}
</addata:{{obj.attr}}>""".strip())


class LdapAttr(object):

    def __init__(self, attr, vals, ldap_syntax, xsi_type='xsd:string'):
        self.attr = attr  # sAMAccountName
        self.ldap_syntax = ldap_syntax
        assert ':' in xsi_type
        self.xsi_type = xsi_type

        if self.xsi_type == 'xsd:base64Binary':
            vals = [b64encode(val) for val in vals]
        self.vals = vals

    def to_xml(self):
        return LDAP_ATTR_TEMPLATE.render({'obj': self})


# https://msdn.microsoft.com/en-us/library/dd340577.aspx
SYNTHETIC_ATTRS = {
    'objectReferenceProperty',
    'container-hierarchy-parent',
    'distinguishedName',
    'relativeDistinguishedName',
}

SYNTHETIC_ATTR_TEMPLATE = jinja2.Template("""
<ad:{{obj.attr}}>
   {%- for val in obj.vals %}
   <ad:value xsi:type="{{obj.xsi_type}}">{{val}}</ad:value>
   {%- endfor %}
</ad:{{obj.attr}}>""".strip())


class SyntheticAttr(object):

    def __init__(self, attr, vals, xsi_type='xsd:string'):
        assert attr in SYNTHETIC_ATTRS
        self.attr = attr
        self.xsi_type = xsi_type

        # FIXME: could be other iterable
        if not isinstance(vals, list):
            vals = [vals]
        if self.xsi_type == 'xsd:base64Binary':
            vals = [b64encode(val) for val in vals]
        self.vals = vals

    def to_xml(self):
        return SYNTHETIC_ATTR_TEMPLATE.render({'obj': self})

def get_rdn(dn):
    rdn_name = dn.get_rdn_name()
    rdn_value = dn.get_rdn_value()
    if rdn_name and rdn_value:
        return '%s=%s' % (rdn_name, rdn_value)
    return ''


class SamDBHelper(SamDB):

    def __init__(self):
        lp = LoadParm()
        lp.load_default()
        SamDB.__init__(self, lp=lp, session_info=system_session())

    def search_scope_base(self, *args, **kwargs):
        kwargs['scope'] = ldb.SCOPE_BASE
        return self.search(*args, **kwargs)

    def search_scope_onelevel(self, *args, **kwargs):
        kwargs['scope'] = ldb.SCOPE_ONELEVEL
        return self.search(*args, **kwargs)

    def search_scope_subtree(self, *args, **kwargs):
        kwargs['scope'] = ldb.SCOPE_SUBTREE
        return self.search(*args, **kwargs)

    def get_rootdse_attr_schema_syntax(self, attr):
        oid = ROOT_DSE_ATTRS.get(attr)
        return oid and OID_SCHEMA_SYNTAX_DICT.get(oid) or None

    def get_attr_schema_syntax(self, attr, is_root_dse=False):
        if is_root_dse:
            oid = ROOT_DSE_ATTRS.get(attr)
        else:
            oid = self.get_syntax_oid_from_lDAPDisplayName(attr)
        return oid and OID_SCHEMA_SYNTAX_DICT.get(oid) or None

    def build_attr_list(self, msg, is_root_dse=False, attr_names=[]):
        if not attr_names:
            attr_names = list(msg.keys())
            attr_names.remove('dn')
            attr_names.remove('vendorName')

        attrs = []
        for attr_name in attr_names:
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


    def render_root_dse_xml(self, **context):
        # ldb.Result
        result = self.search(base='', scope=ldb.SCOPE_BASE)
        # ldb.MessageElement
        msg = result[0]

        attrs = self.build_attr_list(msg, is_root_dse=True)
        # this one appears first
        attrs.insert(0, SyntheticAttr('objectReferenceProperty', [ROOT_DSE_GUID]))
        # these 3 appear at last
        attrs.append(SyntheticAttr('container-hierarchy-parent', [ROOT_DSE_GUID]))
        attrs.append(SyntheticAttr('relativeDistinguishedName', ['']))
        attrs.append(SyntheticAttr('distinguishedName', ['']))
        context['attrs'] = attrs
        return render_template('root-DSE.xml', **context)


    def render_msds_portldap(self, **context):
        # return a fixed xml for now
        return render_template('msDS-PortLDAP.xml', **context)

    # def render_get(identifier, attrs, controls, **kwargs):
    def render_transfer_get(self, **context):
        # the attrs client is asking for, e.g: addata:msDS-PortLDAP
        AttributeType_List = context['AttributeType_List']
        # attrs without ns prefix, keep the order which matters
        attr_names = [attr.split(':')[-1] for attr in AttributeType_List]

        result = self.search(
            base=context['objectReferenceProperty'],
            attrs=attr_names,
            controls=[])

        msg = result[0]

        attrs = self.build_attr_list(msg, attr_names=attr_names)
        # attrs.append(SyntheticAttr('distinguishedName', [str(msg.dn)]))
        # attrs.append(SyntheticAttr('relativeDistinguishedName', ['TODO']))
        context['attrs'] = attrs

        return render_template('transfer-Get.xml', **context)

    def render_enumerate(self, **context):
        return render_template('Enumerate.xml', **context)

    def render_pull(self, **context):
        SelectionProperty_List = context['SelectionProperty_List']
        enumeration_context = context['EnumerationContext']
        cookie = enumeration_context.get('cookie', '')

        attr_names = [attr.split(':')[-1] for attr in SelectionProperty_List]
        LdapQuery = context['LdapQuery']
        MaxElements = context['MaxElements']

        scope = SCOPE_ADLQ_TO_LDB[LdapQuery['Scope'].lower()]
        result = self.search(
            base=LdapQuery['BaseObject'],
            scope=scope,
            expression=LdapQuery['Filter'],
            attrs=attr_names,
            controls=['paged_results:1:%s%s' % (MaxElements, cookie)]
        )

        ctrls = [str(c) for c in result.controls if
                 str(c).startswith("paged_results")]
        spl = ctrls[0].rsplit(':', 3)
        if len(spl) == 3:
            new_cookie = ':' + spl[-1]
            enumeration_context['cookie'] = new_cookie
            context['is_end'] = False
        else:
            # Set finish sequence
            context['is_end'] = True

        objects = [
            self.build_attr_list(msg, attr_names=attr_names)
            for msg in result.msgs
        ]
        context['objects'] = objects
        # import ipdb; ipdb.set_trace()

        return render_template('Pull.xml', **context)


if __name__ == '__main__':
    from IPython import embed
    embed(header='Samba Python Shell')
