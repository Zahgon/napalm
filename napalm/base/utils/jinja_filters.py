"""Some common jinja filters."""

from typing import Dict, Any


class CustomJinjaFilters(object):
    """Utility filters for jinja2."""

    @classmethod
    def filters(cls) -> Dict:
        """Return jinja2 filters that this module provide."""
        pass


def oc_attr_isdefault(o: Any) -> bool:
    """Return wether an OC attribute has been defined or not."""
    pass


def openconfig_to_cisco_af(value: str) -> str:
    """Translate openconfig AF name to Cisco AFI name."""
    pass


def openconfig_to_eos_af(value: str) -> str:
    """Translate openconfig AF name to EOS AFI name."""
    pass
