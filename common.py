import xmlschema

def build_xml_schema():
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

    return xs

