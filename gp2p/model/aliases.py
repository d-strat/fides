from ctypes import Union

IP = str
"""IPv4, IPv6 in string representation."""

Domain = str
"""Host Name, Domain."""

PeerId = str
"""String representation of peer's public key. """

OrganisationId = str
"""String representation of organisation ID."""

Target = Union[IP, Domain]
"""Intelligence Target - domain or IP."""

ConfidentialityLevel = float
"""Confidentiality level for threat intelligence.

If an entity needs to have access to any data, it must mean

entity.confidentiality_level >= data.confidentiality_level

thus level 0 means accessible for everybody 
"""
