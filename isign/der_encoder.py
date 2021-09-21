import six

import asn1

def der_encode(element):
    encoder = asn1.Encoder()
    encoder.start()
    _der_encode(element, encoder)
    return encoder.output()

def _der_encode(element, encoder):
    if isinstance(element, dict):
        encoder.enter(asn1.Numbers.Set)
        for element_key,element_value in six.iteritems(element):
            encoder.enter(asn1.Numbers.Sequence)
            _der_encode(element_key, encoder)
            _der_encode(element_value, encoder)
            encoder.leave()
        encoder.leave()
    elif isinstance(element, list):
        encoder.enter(asn1.Numbers.Sequence)
        for element_item in element:
            _der_encode(element_item, encoder)
        encoder.leave()
    elif isinstance(element, bool):
        encoder.write(element, asn1.Numbers.Boolean)
    elif isinstance(element, int):
        encoder.write(element, asn1.Numbers.Integer)
    elif isinstance(element, str):
        encoder.write(element, asn1.Numbers.UTF8String)
    elif isinstance(element, bytes):
        encoder.write(element, asn1.Numbers.OctetString)
    elif element is None:
        encoder.write(element, asn1.Numbers.Null)
    else:
        raise ValueError('Unsupported type for DER: {}'.format(type(element)))
