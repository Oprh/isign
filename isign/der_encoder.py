import six

from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1.type import char


def encode(element):
    der_object = _turn_into_der_structure(element)
    return encoder.encode(der_object)

def _turn_into_der_structure(element):
    if isinstance(element, dict):
        set_element = univ.SetOf()
        for set_index, (element_key,element_value) in enumerate(six.iteritems(element)):
            entry_sequence = univ.Sequence()
            entry_sequence[0] = _turn_into_der_structure(element_key)
            entry_sequence[1] = _turn_into_der_structure(element_value)
            set_element[set_index] = entry_sequence
        return set_element
    elif isinstance(element, list):
        sequence_element = univ.Sequence()
        for sequence_index, element_item in enumerate(element):
            sequence_element[sequence_index] = _turn_into_der_structure(element_item)
        return sequence_element
    elif isinstance(element, bool):
        return univ.Boolean(element)
    elif isinstance(element, int):
        return univ.Integer(element)
    elif isinstance(element, str):
        return char.UTF8String(element)
    elif isinstance(element, bytes):
        return univ.OctetString(element)
    elif element is None:
        return univ.Null()
    else:
        raise ValueError('Unsupported type for DER: {}'.format(type(element)))
