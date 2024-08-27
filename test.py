import xmlschema
import lxml.etree as ElementTree
import pprint
import lxml

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

a= xs.to_dict("traces/02-portldap-get.xml")

#xt = ElementTree.parse('traces/02-portldap-get.xml')
#a = xs.to_dict(xt)
#pprint.pprint(a)
#print(a)

print(xs.encode(a, path="s:Envelope"))
#xs.encode({'Envelope': a})
a= xs.to_dict("traces/02-portldap-get-response.xml")
print(a)
#print(pprint.pprint(a))
import xml.etree.ElementTree as ET
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

#print(ET.tostring(xs.encode(a, path="s:Envelope", namespaces=NAMESPACES)))
print(xs.encode(a, path="s:Envelope"))

a= xs.to_dict("traces/01-rootdse-get.xml")
print(xs.encode(a, path="s:Envelope"))
#print(a)
#print(pprint.pprint(a))
a= xs.to_dict("traces/01-rootdse-get-response.xml")
print(xs.encode(a, path="s:Envelope"))
#print(pprint.pprint(a))
#print(a)

et = ElementTree.fromstring(open("traces/03-enumerate.xml").read())
#a= xs.to_dict(et, namespaces=NAMESPACES)
a= xs.to_dict(et)
#pprint.pprint(a)
a= xs.to_dict("traces/03-enumerate.xml")
#print(pprint.pprint(a))
#print(ET.tostring(xs.encode(a, path="s:Envelope", namespaces=NAMESPACES)))
#print(pprint.pprint(a))
a['s:Header']['ad:instance']= "中文"
#print(xmlschema.etree_tostring(xs.encode(a, path="s:Envelope"), NAMESPACES))
print(ElementTree.tostring(xs.encode(a, path="s:Envelope", etree_element_class=lxml.etree.Element)).decode())
print(xs.encode(a, path="s:Envelope"))

a= xs.to_dict("traces/03-enumerate-response.xml")
print(xs.encode(a, path="s:Envelope"))

a= xs.to_dict("traces/04-enumerate-pull.xml")
print(xs.encode(a, path="s:Envelope"))

a= xs.to_dict("traces/04-enumerate-pull-response.xml")
print(a)

print(xs.encode(a, path="s:Envelope"))

a= xs.to_dict("traces/05-create-fault.xml")
#pprint.pprint(a)
print(xs.encode(a, path="s:Envelope"))

a= xs.to_dict("traces/05-create.xml")
#print(a)
print(xs.encode(a, path="s:Envelope"))

a= xs.to_dict("traces/06-delete.xml")
#print(a)
print(xs.encode(a, path="s:Envelope"))
