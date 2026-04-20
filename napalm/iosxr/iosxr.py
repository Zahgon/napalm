# -*- coding: utf-8 -*-
# Copyright 2015 Spotify AB. All rights reserved.
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

# import stdlib
import re
import copy
import ipaddress
from collections import defaultdict
import logging

# import third party lib
from lxml import etree as ETREE

from napalm.pyIOSXR import IOSXR
from napalm.pyIOSXR.exceptions import ConnectError
from napalm.pyIOSXR.exceptions import TimeoutError
from napalm.pyIOSXR.exceptions import InvalidInputError
from napalm.pyIOSXR.exceptions import XMLCLIError

# import NAPALM base
import napalm.base.helpers
from napalm.base.netmiko_helpers import netmiko_args
from napalm.iosxr import constants as C
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import ReplaceConfigException
from napalm.base.exceptions import CommandTimeoutException

logger = logging.getLogger(__name__)
IP_RIBRoute = "IP_RIBRoute"


class IOSXRDriver(NetworkDriver):
    """IOS-XR driver class: inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        if optional_args is None:
            optional_args = {}
        self.lock_on_connect = optional_args.get("config_lock", False)

        self.netmiko_optional_args = netmiko_args(optional_args)
        try:
            self.port = self.netmiko_optional_args.pop("port")
        except KeyError:
            self.port = 22

        self.platform = "iosxr"
        self.device = IOSXR(
            hostname,
            username,
            password,
            timeout=timeout,
            port=self.port,
            lock=self.lock_on_connect,
            **self.netmiko_optional_args,
        )

    def open(self):
        pass

    def close(self):
        logger.debug("Closed connection with device %s" % (self.hostname))
        self.device.close()

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        if self.device is None:
            return {"is_alive": False}
        # Simply returns the flag from pyIOSXR
        return {"is_alive": self.device.is_alive()}

    def load_replace_candidate(self, filename=None, config=None):
        pass

    def load_merge_candidate(self, filename=None, config=None):
        pass

    def compare_config(self):
        if not self.pending_changes:
            return ""
        elif self.replace:
            return self.device.compare_replace_config().strip()
        else:
            return self.device.compare_config().strip()

    def commit_config(self, message="", revert_in=None):
        if revert_in is not None:
            raise NotImplementedError("Commit confirm has not been implemented on this platform.")
        commit_args = {"comment": message} if message else {}
        if self.replace:
            self.device.commit_replace_config(**commit_args)
        else:
            self.device.commit_config(**commit_args)
        self.pending_changes = False
        if not self.lock_on_connect:
            self.device.unlock()

    def discard_config(self):
        self.device.discard_config()
        self.pending_changes = False
        if not self.lock_on_connect:
            self.device.unlock()

    def rollback(self):
        self.device.rollback()

    def get_facts(self):
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

        facts_rpc_request = """
<Get>
  <Operational>
    <SystemTime/>
    <PlatformInventory>
      <RackTable>
        <Rack>
          <Naming>
            <Name>0</Name>
          </Naming>
          <Attributes>
            <BasicInfo/>
          </Attributes>
        </Rack>
      </RackTable>
    </PlatformInventory>
  </Operational>
</Get>
        """

        # IOS-XR 7.3.3 and possibly other 7.X versions have this located in
        # different location in the XML tree
        facts_rpc_request_alt = """
<Get>
  <Operational>
    <SystemTime/>
    <Inventory>
      <Entities>
        <Entity>
          <Naming>
            <Name>Rack 0</Name>
          </Naming>
          <Attributes>
            <InvBasicBag></InvBasicBag>
          </Attributes>
        </Entity>
      </Entities>
    </Inventory>
  </Operational>
</Get>
"""

        system_time_xpath = ".//SystemTime/Uptime"
        try:
            facts_rpc_reply = ETREE.fromstring(self.device.make_rpc_call(facts_rpc_request))
            platform_attr_xpath = ".//RackTable/Rack/Attributes/BasicInfo"
        except XMLCLIError:
            facts_rpc_reply = ETREE.fromstring(self.device.make_rpc_call(facts_rpc_request_alt))
            platform_attr_xpath = ".//Entities/Entity/Attributes/InvBasicBag"

        system_time_tree = facts_rpc_reply.xpath(system_time_xpath)[0]
        try:
            platform_attr_tree = facts_rpc_reply.xpath(platform_attr_xpath)[0]
        except IndexError:
            platform_attr_tree = facts_rpc_reply.xpath(platform_attr_xpath)

        hostname = napalm.base.helpers.convert(
            str, napalm.base.helpers.find_txt(system_time_tree, "Hostname")
        )
        uptime = napalm.base.helpers.convert(
            float, napalm.base.helpers.find_txt(system_time_tree, "Uptime"), -1.0
        )
        serial = napalm.base.helpers.convert(
            str, napalm.base.helpers.find_txt(platform_attr_tree, "SerialNumber")
        )
        os_version = napalm.base.helpers.convert(
            str, napalm.base.helpers.find_txt(platform_attr_tree, "SoftwareRevision")
        )
        model = napalm.base.helpers.convert(
            str, napalm.base.helpers.find_txt(platform_attr_tree, "ModelName")
        )
        interface_list = sorted(list(self.get_interfaces().keys()))

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
        interfaces = {}

        INTERFACE_DEFAULTS = {
            "is_enabled": False,
            "is_up": False,
            "mac_address": "",
            "description": "",
            "speed": -1.0,
            "last_flapped": -1.0,
        }

        interfaces_rpc_request = "<Get><Operational><Interfaces/></Operational></Get>"

        interfaces_rpc_reply = ETREE.fromstring(self.device.make_rpc_call(interfaces_rpc_request))

        for interface_tree in interfaces_rpc_reply.xpath(".//Interfaces/InterfaceTable/Interface"):
            interface_name = napalm.base.helpers.find_txt(interface_tree, "Naming/InterfaceName")
            if not interface_name:
                continue
            is_up = napalm.base.helpers.find_txt(interface_tree, "LineState") == "IM_STATE_UP"
            enabled = napalm.base.helpers.find_txt(interface_tree, "State") != "IM_STATE_ADMINDOWN"
            raw_mac = napalm.base.helpers.find_txt(interface_tree, "MACAddress/Address")
            mac_address = napalm.base.helpers.convert(napalm.base.helpers.mac, raw_mac, raw_mac)
            speed = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.convert(
                    float, napalm.base.helpers.find_txt(interface_tree, "Bandwidth"), 0
                )
                * 1e-3,
            )

            mtu = int(napalm.base.helpers.find_txt(interface_tree, "MTU"))
            description = napalm.base.helpers.find_txt(interface_tree, "Description")
            last_flapped = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(interface_tree, "LastStateTransitionTime", -1),
                -1,
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
                    "last_flapped": (last_flapped / 1e9 if last_flapped != -1.0 else -1.0),
                }
            )

        return interfaces

    def get_interfaces_counters(self):
        pass

    def get_bgp_neighbors(self):
        pass

    def get_environment(self):
        pass

    def get_lldp_neighbors(self):
        # init result dict
        pass

    def get_lldp_neighbors_detail(self, interface=""):
        pass

    def cli(self, commands, encoding="text"):
        if encoding not in ("text",):
            raise NotImplementedError("%s is not a supported encoding" % encoding)

        cli_output = {}

        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            try:
                cli_output[str(command)] = str(self.device._execute_show(command))
            except TimeoutError:
                cli_output[str(command)] = 'Execution of command \
                    "{command}" took too long! Please adjust your params!'.format(command=command)
                logger.error(str(cli_output))
                raise CommandTimeoutException(str(cli_output))

        return cli_output

    def get_bgp_config(self, group="", neighbor=""):
        pass

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        pass

    def get_arp_table(self, vrf=""):
        pass

    def get_ntp_peers(self):
        pass

    def get_ntp_servers(self):
        pass

    def get_ntp_stats(self):
        pass

    def get_interfaces_ip(self):
        pass

    def get_mac_address_table(self):
        pass

    def get_route_to(self, destination="", protocol="", longer=False):
        pass

    def get_snmp_information(self):
        pass

    def get_probes_config(self):
        pass

    def get_probes_results(self):
        pass

    def traceroute(
        self,
        destination,
        source=C.TRACEROUTE_SOURCE,
        ttl=C.TRACEROUTE_TTL,
        timeout=C.TRACEROUTE_TIMEOUT,
        vrf=C.TRACEROUTE_VRF,
    ):
        pass

    def get_users(self):
        pass

    def get_config(self, retrieve="all", full=False, sanitized=False, format="text"):
        config = {"startup": "", "running": "", "candidate": ""}  # default values

        # IOS-XR only supports "all" on "show run"
        run_full = " all" if full else ""

        filter_strings = [r"^Building configuration.*$", r"^!! IOS XR Configuration.*$"]
        filter_pattern = napalm.base.helpers.generate_regex_or(filter_strings)

        if retrieve.lower() in ["running", "all"]:
            running = str(self.device._execute_config_show(f"show running-config{run_full}"))
            running = re.sub(filter_pattern, "", running, flags=re.M)
            config["running"] = running
        if retrieve.lower() in ["candidate", "all"]:
            candidate = str(self.device._execute_config_show("show configuration merge"))
            candidate = re.sub(filter_pattern, "", candidate, flags=re.M)
            config["candidate"] = candidate

        if sanitized:
            return napalm.base.helpers.sanitize_configs(config, C.CISCO_SANITIZE_FILTERS)

        return config
