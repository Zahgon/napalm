# -*- coding: utf-8 -*-
# Copyright 2020 CISCO. All rights reserved.
# Copyright 2021 Kirk Byers. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""NETCONF Driver for IOSXR devices."""

from __future__ import unicode_literals

# import stdlib
import re
import copy
import difflib
import ipaddress
import logging

# import third party lib
from ncclient import manager
from ncclient.xml_ import to_ele
from ncclient.operations.rpc import RPCError
from ncclient.operations.errors import TimeoutExpiredError
from lxml import etree as ETREE
from lxml.etree import XMLSyntaxError

# import NAPALM base
from napalm.iosxr_netconf import constants as C
from napalm.iosxr.utilities import strip_config_header
from napalm.base.base import NetworkDriver
import napalm.base.helpers
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import ReplaceConfigException

logger = logging.getLogger(__name__)


class IOSXRNETCONFDriver(NetworkDriver):
    """IOS-XR NETCONF driver class: inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize IOSXR driver.

        optional_args:
            * config_lock (True/False): lock configuration DB after the
                connection is established.
            * port (int): custom port
            * key_file (string): SSH key file path
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        self.locked = False
        self.optional_args = optional_args if optional_args else {}
        self.port = self.optional_args.pop("port", 830)
        self.lock_on_connect = self.optional_args.pop("config_lock", False)
        self.key_file = self.optional_args.pop("key_file", None)
        self.config_encoding = self.optional_args.pop("config_encoding", "cli")
        if "ssh_config_file" in self.optional_args:
            self.optional_args["ssh_config"] = self.optional_args.pop("ssh_config_file")
        if self.config_encoding not in C.CONFIG_ENCODINGS:
            raise ValueError(f"config encoding must be one of {C.CONFIG_ENCODINGS}")

        self.platform = "iosxr_netconf"
        self.device = None
        self.module_set_ns = []

    def open(self):
        """Open the connection with the device."""
        pass

    def close(self):
        """Close the connection."""
        logger.debug("Closed connection with device %s" % (self.hostname))
        self._unlock()
        self.device.close_session()

    def _lock(self):
        """Lock the config DB."""
        pass

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            self.device.unlock()
            self.locked = False

    def _load_config(self, filename, config):
        """Edit Configuration."""
        pass

    def _filter_config_tree(self, tree):
        """Return filtered config etree based on YANG module set."""
        if self.module_set_ns:

            def unexpected(n):
                return n not in self.module_set_ns

        else:

            def unexpected(n):
                return n.startswith("http://openconfig.net/yang")

        for subtree in tree:
            if unexpected(subtree.tag[1:].split("}")[0]):
                tree.remove(subtree)
        return tree

    def _unexpected_modules(self, tree):
        """Return list of unexpected modules based on YANG module set."""
        pass

    def is_alive(self):
        """Return flag with the state of the connection."""
        if self.device is None:
            return {"is_alive": False}
        return {"is_alive": self.device._session.transport.is_active()}

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        pass

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        pass

    def compare_config(self):
        """Compare candidate config with running."""

        diff = ""
        encoding = self.config_encoding
        if encoding not in C.CLI_DIFF_RPC_REQ:
            raise NotImplementedError(f"config encoding must be one of {C.CONFIG_ENCODINGS}")

        if self.pending_changes:
            parser = ETREE.XMLParser(remove_blank_text=True)
            if encoding == "cli":
                diff = self.device.dispatch(to_ele(C.CLI_DIFF_RPC_REQ)).xml
                diff = ETREE.XML(diff, parser=parser)[0].text.strip()
                diff = strip_config_header(diff)
            elif encoding == "xml":
                run_conf = self.device.get_config("running").xml
                can_conf = self.device.get_config("candidate").xml
                run_conf = ETREE.tostring(
                    self._filter_config_tree(ETREE.XML(run_conf, parser=parser)[0]),
                    pretty_print=True,
                ).decode()
                can_conf = ETREE.tostring(
                    self._filter_config_tree(ETREE.XML(can_conf, parser=parser)[0]),
                    pretty_print=True,
                ).decode()
                for line in difflib.unified_diff(run_conf.splitlines(1), can_conf.splitlines(1)):
                    diff += line

        return diff

    def commit_config(self, message="", revert_in=None):
        """Commit configuration."""
        if revert_in is not None:
            raise NotImplementedError("Commit confirm has not been implemented on this platform.")
        if message:
            raise NotImplementedError("Commit message not implemented for this platform")
        self.device.commit()
        self.pending_changes = False
        self._unlock()

    def discard_config(self):
        """Discard changes."""
        self.device.discard_changes()
        self.pending_changes = False
        self._unlock()

    def rollback(self):
        """Rollback to previous commit."""
        self.device.dispatch(to_ele(C.ROLLBACK_RPC_REQ))

    def _find_txt(self, xml_tree, path, default=None, namespaces=None):
        """
        Extract the text value from a leaf in an XML tree using XPath.

        Will return a default value if leaf path not matched.
        :param xml_tree:the XML Tree object. <type'lxml.etree._Element'>.
        :param path: XPath to be applied in order to extract the desired data.
        :param default:  Value to be returned in case of a no match.
        :param namespaces: namespace dictionary.
        :return: a str value or None if leaf path not matched.
        """

        value = None
        xpath_applied = xml_tree.xpath(path, namespaces=namespaces)
        if xpath_applied:
            if not len(xpath_applied[0]):
                if xpath_applied[0].text is not None:
                    value = xpath_applied[0].text.strip()
                else:
                    value = ""
        else:
            value = default

        return value

    def get_facts(self):
        """Return facts of the device."""
        facts = {
            "vendor": "Cisco",
            "os_version": "",
            "hostname": "",
            "uptime": -1.0,
            "serial_number": "",
            "fqdn": "",
            "model": "",
            "interface_list": [],
        }
        interface_list = []

        facts_rpc_reply = self.device.dispatch(to_ele(C.FACTS_RPC_REQ)).xml

        # Converts string to etree
        facts_rpc_reply_etree = ETREE.fromstring(facts_rpc_reply)

        # Retrieves hostname
        hostname = napalm.base.helpers.convert(
            str,
            self._find_txt(
                facts_rpc_reply_etree,
                ".//suo:system-time/\
            suo:uptime/suo:host-name",
                default="",
                namespaces=C.NS,
            ),
        )

        # Retrieves uptime
        uptime = napalm.base.helpers.convert(
            float,
            self._find_txt(
                facts_rpc_reply_etree,
                ".//suo:system-time/\
            suo:uptime/suo:uptime",
                default="",
                namespaces=C.NS,
            ),
            -1.0,
        )

        # Retrieves interfaces name
        interface_tree = facts_rpc_reply_etree.xpath(
            ".//int:interfaces/int:interfaces/int:interface", namespaces=C.NS
        )
        for interface in interface_tree:
            name = self._find_txt(interface, "./int:interface-name", default="", namespaces=C.NS)
            interface_list.append(name)
        # Retrieves os version, model, serial number
        basic_info_tree = facts_rpc_reply_etree.xpath(
            ".//imo:inventory/imo:entities/imo:entity/imo:attributes/\
                        imo:inv-basic-bag",
            namespaces=C.NS,
        )
        if basic_info_tree:
            os_version = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    basic_info_tree[0],
                    "./imo:software-revision",
                    default="",
                    namespaces=C.NS,
                ),
            )
            model = napalm.base.helpers.convert(
                str,
                self._find_txt(basic_info_tree[0], "./imo:model-name", default="", namespaces=C.NS),
            )
            serial = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    basic_info_tree[0],
                    "./imo:serial-number",
                    default="",
                    namespaces=C.NS,
                ),
            )
        else:
            os_version = ""
            model = ""
            serial = ""

        facts.update(
            {
                "os_version": os_version,
                "hostname": hostname,
                "model": model,
                "uptime": uptime,
                "serial_number": serial,
                "fqdn": hostname,
                "interface_list": interface_list,
            }
        )

        return facts

    def get_interfaces(self):
        """Return interfaces details."""
        interfaces = {}

        INTERFACE_DEFAULTS = {
            "is_enabled": False,
            "is_up": False,
            "mac_address": "",
            "description": "",
            "speed": -1.0,
            "last_flapped": -1.0,
        }

        interfaces_rpc_reply = self.device.get(filter=("subtree", C.INT_RPC_REQ_FILTER)).xml
        # Converts string to etree
        interfaces_rpc_reply_etree = ETREE.fromstring(interfaces_rpc_reply)

        # Retrieves interfaces details
        for interface_tree, description_tree in zip(
            interfaces_rpc_reply_etree.xpath(
                ".//int:interfaces/int:interface-xr/int:interface", namespaces=C.NS
            ),
            interfaces_rpc_reply_etree.xpath(
                ".//int:interfaces/int:interfaces/int:interface", namespaces=C.NS
            ),
        ):
            interface_name = self._find_txt(
                interface_tree, "./int:interface-name", default="", namespaces=C.NS
            )
            if not interface_name:
                continue
            is_up = (
                self._find_txt(interface_tree, "./int:line-state", default="", namespaces=C.NS)
                == "im-state-up"
            )
            enabled = (
                self._find_txt(interface_tree, "./int:state", default="", namespaces=C.NS)
                != "im-state-admin-down"
            )
            raw_mac = self._find_txt(
                interface_tree,
                "./int:mac-address/int:address",
                default="",
                namespaces=C.NS,
            )
            mac_address = napalm.base.helpers.convert(napalm.base.helpers.mac, raw_mac, raw_mac)
            speed = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.convert(
                    float,
                    self._find_txt(interface_tree, "./int:bandwidth", namespaces=C.NS),
                    0,
                )
                * 1e-3,
            )
            mtu = int(self._find_txt(interface_tree, "./int:mtu", default="", namespaces=C.NS))
            description = self._find_txt(
                description_tree, "./int:description", default="", namespaces=C.NS
            )
            interfaces[interface_name] = copy.deepcopy(INTERFACE_DEFAULTS)
            interfaces[interface_name].update(
                {
                    "is_up": is_up,
                    "speed": speed,
                    "mtu": mtu,
                    "is_enabled": enabled,
                    "mac_address": mac_address,
                    "description": description,
                }
            )

        return interfaces

    def get_interfaces_counters(self):
        """Return interfaces counters."""
        pass

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""
        pass

    def get_environment(self):
        """Return environment details."""
        pass

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        pass

    def get_lldp_neighbors_detail(self, interface=""):
        """Detailed view of the LLDP neighbors."""
        pass

    def cli(self, commands, encoding="text"):
        """Execute raw CLI commands and returns their output."""
        return NotImplementedError

    def get_bgp_config(self, group="", neighbor=""):
        """Return BGP configuration."""
        pass

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Detailed view of the BGP neighbors operational data."""
        pass

    def get_arp_table(self, vrf=""):
        """Return the ARP table."""
        pass

    def get_ntp_peers(self):
        """Return the NTP peers configured on the device."""
        pass

    def get_ntp_servers(self):
        """Return the NTP servers configured on the device."""
        pass

    def get_ntp_stats(self):
        """Return NTP stats (associations)."""
        pass

    def get_interfaces_ip(self):
        """Return the configured IP addresses."""
        pass

    def get_mac_address_table(self):
        """Return the MAC address table."""
        pass

    def get_route_to(self, destination="", protocol="", longer=False):
        """Return route details to a specific destination."""
        pass

    def get_snmp_information(self):
        """Return the SNMP configuration."""
        pass

    def get_probes_config(self):
        """Return the configuration of the probes."""
        pass

    def get_probes_results(self):
        """Return the results of the probes."""
        pass

    def traceroute(
        self,
        destination,
        source=C.TRACEROUTE_SOURCE,
        ttl=C.TRACEROUTE_TTL,
        timeout=C.TRACEROUTE_TIMEOUT,
        vrf=C.TRACEROUTE_VRF,
    ):
        """Execute traceroute and return results."""
        pass

    def get_users(self):
        """Return user configuration."""
        pass

    def get_config(self, retrieve="all", full=False, sanitized=False, format="text"):
        """Return device configuration."""

        encoding = self.config_encoding
        # 'full' argument not supported; 'with-default' capability not supported.
        if full:
            raise NotImplementedError(
                "'full' argument has not been implemented on the IOS-XR NETCONF driver"
            )

        if sanitized:
            raise NotImplementedError(
                "sanitized argument has not been implemented on the IOS-XR NETCONF driver"
            )

        # default values
        config = {"startup": "", "running": "", "candidate": ""}
        if encoding == "cli":
            subtree_filter = ("subtree", C.CLI_CONFIG_RPC_REQ_FILTER)
        elif encoding == "xml":
            subtree_filter = None
        else:
            raise NotImplementedError(f"config encoding must be one of {C.CONFIG_ENCODINGS}")

        if retrieve.lower() in ["running", "all"]:
            config["running"] = str(
                self.device.get_config(source="running", filter=subtree_filter).xml
            )
        if retrieve.lower() in ["candidate", "all"]:
            config["candidate"] = str(
                self.device.get_config(source="candidate", filter=subtree_filter).xml
            )

        parser = ETREE.XMLParser(remove_blank_text=True)
        # Validate XML config strings and remove rpc-reply tag
        for datastore in config:
            if config[datastore] != "":
                if encoding == "cli":
                    cli_tree = ETREE.XML(config[datastore], parser=parser)[0]
                    if len(cli_tree):
                        config[datastore] = cli_tree[0].text.strip()
                    else:
                        config[datastore] = ""
                else:
                    config[datastore] = ETREE.tostring(
                        self._filter_config_tree(ETREE.XML(config[datastore], parser=parser)[0]),
                        pretty_print=True,
                        encoding="unicode",
                    )
        if sanitized and encoding == "cli":
            return napalm.base.helpers.sanitize_configs(config, C.CISCO_SANITIZE_FILTERS)
        return config
