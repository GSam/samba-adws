import xmlschema

schema = xmlschema.XMLSchema('https://schemas.xmlsoap.org/ws/2004/09/enumeration/enumeration.xsd')
schema.export(target='./enumeration', save_remote=True)

schema = xmlschema.XMLSchema('https://www.w3.org/2003/05/soap-envelope/')
schema.export(target='./soap', save_remote=True)

schema = xmlschema.XMLSchema('https://schemas.xmlsoap.org/ws/2004/09/transfer/transfer.xsd')
schema.export(target='./transfer', save_remote=True)
