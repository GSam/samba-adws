#!/usr/bin/env python
# coding: utf8
import re

from lxml import etree

NAMESPACES = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://www.w3.org/2005/08/addressing",
    "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
    "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
    "da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "adlq": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery",
    "wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
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


def elem_tostring(elem, pretty_print=True, encoding='unicode'):
    """pretty and unicode by default"""
    return etree.tostring(
        elem, pretty_print=pretty_print, encoding=encoding)



def print_xml(xml, sn=0, mode='w+'):
    # parse to validate
    root = etree.fromstring(xml)
    # print('######################XML HEAD##########################')
    # xml2 = etree.tostring(root, pretty_print=True)
    # print(xml2)
    # print('######################XML TAIL##########################')
    with open('/vagrant/%s.xml' % sn, mode) as f:
        f.write(xml + '\n\n\n')


def rm_whitespaces(text):
    """rm any whitespaces from text"""
    return re.sub(r'\s+', '', text, flags=re.UNICODE)


def compare_xml(xml1, xml2):
    return rm_whitespaces(xml1) == rm_whitespaces(xml2)


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

        self.header = self.get_elem('s:Header')
        self.body = self.get_elem('s:Body')

    def get_elem(self, xpath, as_text=False):
        elem = self.root.find(xpath, namespaces=self.nsmap)
        return elem_get_text(elem) if as_text else elem

    def get_elem_text(self, xpath):
        return self.get_elem(xpath, as_text=True)

    def get_elem_list(self, xpath, as_text=False):
        elems = self.root.findall(xpath, namespaces=self.nsmap)
        return [elem.text.strip() for elem in elems] if as_text else elems

    def is_elem_empty(self, xpath):
        """
        A empty element has no text and children

        e.g.: <s:Body></s:Body>
        """
        elem = self.root.find(xpath, self.nsmap)
        return elem_is_empty(elem)

