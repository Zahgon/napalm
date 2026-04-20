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

import ipaddress
import json
import os
import re
import tempfile
import time
import uuid

# import stdlib
from abc import abstractmethod
from builtins import super
from collections import defaultdict

# import third party lib
from typing import (
    Optional,
    Dict,
    List,
    Union,
    Any,
    cast,
    Callable,
    TypeVar,
)

from typing_extensions import (
    TypedDict,
    DefaultDict,
)

from netmiko import file_transfer
from requests.exceptions import ConnectionError
from netutils.config.compliance import diff_network_config
from netutils.interface import canonical_interface_name

import napalm.base.constants as c

# import NAPALM Base
import napalm.base.helpers
from napalm.base import NetworkDriver
from napalm.base.exceptions import CommandErrorException
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import ReplaceConfigException
from napalm.base.helpers import as_number
from napalm.base.helpers import generate_regex_or
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base import models
from napalm.nxapi_plumbing import Device as NXOSDevice
from napalm.nxapi_plumbing import (
    NXAPIAuthError,
    NXAPIConnectionError,
    NXAPICommandError,
)

F = TypeVar("F", bound=Callable[..., Any])
ShowIPInterfaceReturn = TypedDict(
    "ShowIPInterfaceReturn",
    {
        "intf-name": str,
        "prefix": str,
        "unnum-intf": str,
        "masklen": str,
    },
)


def ensure_netmiko_conn(func: F) -> F:
    """Decorator that ensures Netmiko connection exists."""
    pass


class NXOSDriverBase(NetworkDriver):
    """Common code shared between nx-api and nxos_ssh."""

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: Optional[Dict] = None,
    ) -> None:
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.replace = True
        self.loaded = False
        self.merge_candidate = ""
        self.candidate_cfg = "candidate_config.txt"
        self.rollback_cfg = "rollback_config.txt"
        self._dest_file_system = optional_args.pop("dest_file_system", "bootflash:")
        self.force_no_enable = optional_args.get("force_no_enable", False)
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.device: Optional[NXOSDevice] = None

    @ensure_netmiko_conn
    def load_replace_candidate(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> None:
        pass

    def load_merge_candidate(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> None:
        pass

    def _send_command(
        self, command: str, raw_text: bool = False
    ) -> Dict[str, Union[str, Dict[str, Any]]]:
        raise NotImplementedError

    def _check_file_exists(self, cfg_file: str) -> bool:
        """
        Check that the file exists on remote device using full path.

        cfg_file can be a full path, e.g.: bootflash:rollback_config.txt
        or just a filename, e.g.: rollback_config.txt

        For example
        # dir rollback_config.txt
            71803    Sep 06 14:13:33 2023  rollback_config.txt

        Usage for bootflash://sup-local
        6211682304 bytes used
        110314684416 bytes free
        116526366720 bytes total
        """
        cmd = f"dir {cfg_file}"
        output = self._send_command(command=cmd, raw_text=True)
        if "No such file or directory" in output:
            return False
        else:
            return True

    def _commit_merge(self) -> None:
        try:
            output = self._send_config(self.merge_candidate)
            if output and "Invalid command" in output:
                raise MergeConfigException("Error while applying config!")
        except Exception as e:
            self.rollback()
            err_header = "Configuration merge failed; automatic rollback attempted"
            merge_error = "{0}:\n{1}".format(err_header, repr(str(e)))
            raise MergeConfigException(merge_error)

        # clear the merge buffer
        self.merge_candidate = ""

    def _get_merge_diff(self) -> str:
        """
        Uses netutils diff_network_config to create a partial configuration
        with the proper hierarchy.
        Note: the netutils utility performs the diff offline.

        Returns: diff with the proper hierarchy of commands
        that are missing from the current config.
        Examples:
        Candidate configuration:
        interface loopback0
          ip address 10.1.4.5/32
          ip router ospf 100 area 0.0.0.1

        Base (on device) - relevant section:
        ...
        interface loopback0
          ip address 10.1.4.4/32
          ip router ospf 100 area 0.0.0.1
        ...

        Diff that respects the required command hierarchy:
        interface loopback0
          ip address 10.1.4.5/32
        """
        running_config = self.get_config(retrieve="running", full=True)["running"]
        return diff_network_config(self.merge_candidate, running_config, "cisco_nxos")

    def _get_diff(self) -> str:
        """Get a diff between running config and a proposed file."""
        diff: List[str] = []
        self._create_sot_file()
        diff_out = self._send_command(
            "show diff rollback-patch file {} file {}".format("sot_file", self.candidate_cfg),
            raw_text=True,
        )
        assert isinstance(diff_out, str)
        try:
            diff_out = (
                diff_out.split("Generating Rollback Patch")[1]
                .replace("Rollback Patch is Empty", "")
                .strip()
            )
            for line in diff_out.splitlines():
                if line:
                    if line[0].strip() != "!" and line[0].strip() != ".":
                        diff.append(line.rstrip(" "))
        except (AttributeError, KeyError):
            raise ReplaceConfigException(
                "Could not calculate diff. It's possible the given file doesn't exist."
            )
        return "\n".join(diff)

    def compare_config(self) -> str:
        if self.loaded:
            if not self.replace:
                return self._get_merge_diff()
            diff = self._get_diff()
            return diff
        return ""

    def commit_config(self, message: str = "", revert_in: Optional[int] = None) -> None:
        if revert_in is not None:
            raise NotImplementedError("Commit confirm has not been implemented on this platform.")
        if message:
            raise NotImplementedError("Commit message not implemented for this platform")
        if self.loaded:
            # Create checkpoint from current running-config
            self._save_to_checkpoint(self.rollback_cfg)

            if self.replace:
                self._load_cfg_from_checkpoint()
            else:
                self._commit_merge()

            try:
                # If hostname changes ensure Netmiko state is updated properly
                self._netmiko_device.set_base_prompt()
            except AttributeError:
                pass

            self._copy_run_start()
            self.loaded = False
        else:
            raise ReplaceConfigException("No config loaded.")

    def discard_config(self) -> None:
        if self.loaded:
            # clear the buffer
            self.merge_candidate = ""
        if self.loaded and self.replace:
            self._delete_file(self.candidate_cfg)
        self.loaded = False

    def _create_sot_file(self) -> None:
        """Create Source of Truth file to compare."""

        # Bug on on NX-OS 6.2.16 where overwriting sot_file would take exceptionally long time
        # (over 12 minutes); so just delete the sot_file
        try:
            self._delete_file(filename="sot_file")
        except Exception:
            pass
        commands = [
            "terminal dont-ask",
            "checkpoint file sot_file",
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    def ping(
        self,
        destination: str,
        source: str = c.PING_SOURCE,
        ttl: int = c.PING_TTL,
        timeout: int = c.PING_TIMEOUT,
        size: int = c.PING_SIZE,
        count: int = c.PING_COUNT,
        vrf: str = c.PING_VRF,
        source_interface: str = c.PING_SOURCE_INTERFACE,
    ) -> models.PingResultDict:
        """
        Execute ping on the device and returns a dictionary with the result.
        Output dictionary has one of following keys:
            * success
            * error
        In case of success, inner dictionary will have the followin keys:
            * probes_sent (int)
            * packet_loss (int)
            * rtt_min (float)
            * rtt_max (float)
            * rtt_avg (float)
            * rtt_stddev (float)
            * results (list)
        'results' is a list of dictionaries with the following keys:
            * ip_address (str)
            * rtt (float)
        """
        pass

    def traceroute(
        self,
        destination: str,
        source: str = c.TRACEROUTE_SOURCE,
        ttl: int = c.TRACEROUTE_TTL,
        timeout: int = c.TRACEROUTE_TIMEOUT,
        vrf: str = c.TRACEROUTE_VRF,
    ) -> models.TracerouteResultDict:
        pass

    def _get_checkpoint_file(self) -> str:
        pass

    def _set_checkpoint(self, filename: str) -> None:
        pass

    def _save_to_checkpoint(self, filename: str) -> None:
        """Save the current running config to the given file."""
        commands = [
            "terminal dont-ask",
            "checkpoint file {}".format(filename),
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    def _delete_file(self, filename: str) -> None:
        commands = [
            "terminal dont-ask",
            "delete {}".format(filename),
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    @staticmethod
    def _create_tmp_file(config: str) -> str:
        pass

    def _disable_confirmation(self) -> None:
        pass

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        # NX-OS adds some extra, unneeded lines that should be filtered.
        filter_strings = [
            r"!Command: show .*$",
            r"!Time:.*\d{4}\s*$",
            r"Startup config saved at:.*$",
        ]
        filter_pattern = generate_regex_or(filter_strings)

        config: models.ConfigDict = {
            "startup": "",
            "running": "",
            "candidate": "",
        }  # default values
        # NX-OS only supports "all" on "show run"
        run_full = " all" if full else ""

        if retrieve.lower() in ("running", "all"):
            command = f"show running-config{run_full}"
            output = self._send_command(command, raw_text=True)
            assert isinstance(output, str)
            output = re.sub(filter_pattern, "", output, flags=re.M)
            config["running"] = output.strip()
        if retrieve.lower() in ("startup", "all"):
            command = "show startup-config"
            output = self._send_command(command, raw_text=True)
            assert isinstance(output, str)
            output = re.sub(filter_pattern, "", output, flags=re.M)
            config["startup"] = output.strip()

        if sanitized:
            return napalm.base.helpers.sanitize_configs(config, c.CISCO_SANITIZE_FILTERS)

        return config

    def get_lldp_neighbors(self) -> Dict[str, List[models.LLDPNeighborDict]]:
        """IOS implementation of get_lldp_neighbors."""
        pass

    def get_lldp_neighbors_detail(self, interface: str = "") -> models.LLDPNeighborsDetailDict:
        pass

    @staticmethod
    def _get_table_rows(parent_table: Optional[Dict], table_name: str, row_name: str) -> List:
        """
        Inconsistent behavior:
        {'TABLE_intf': [{'ROW_intf': {
        vs
        {'TABLE_mac_address': {'ROW_mac_address': [{
        vs
        {'TABLE_vrf': {'ROW_vrf': {'TABLE_adj': {'ROW_adj': {
        """
        if parent_table is None:
            return []
        _table = parent_table.get(table_name)
        _table_rows = []
        if isinstance(_table, list):
            _table_rows = [_table_row.get(row_name) for _table_row in _table]
        elif isinstance(_table, dict):
            _table_rows = _table.get(row_name)  # type: ignore
        if not isinstance(_table_rows, list):
            _table_rows = [_table_rows]
        return _table_rows

    def _get_reply_table(self, result: Optional[Dict], table_name: str, row_name: str) -> List:
        return self._get_table_rows(result, table_name, row_name)

    def _get_command_table(self, command: str, table_name: str, row_name: str) -> List:
        json_output = self._send_command(command)
        if type(json_output) is not dict and json_output:
            assert isinstance(json_output, str)
            json_output = json.loads(json_output)
        return self._get_reply_table(json_output, table_name, row_name)

    def _parse_vlan_ports(self, vlan_s: Union[str, List]) -> List:
        pass

    @abstractmethod
    def _send_config(self, commands: Union[str, List]) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def _load_cfg_from_checkpoint(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def _copy_run_start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def _send_command_list(self, commands: List[str]) -> List[str]:
        raise NotImplementedError


class NXOSDriver(NXOSDriverBase):
    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: Optional[Dict] = None,
    ) -> None:
        super().__init__(hostname, username, password, timeout=timeout, optional_args=optional_args)
        if optional_args is None:
            optional_args = {}

        # nxos_protocol is there for backwards compatibility, transport is the preferred method
        self.transport = optional_args.get("transport", optional_args.get("nxos_protocol", "https"))
        if self.transport == "https":
            self.port = optional_args.get("port", 443)
        elif self.transport == "http":
            self.port = optional_args.get("port", 80)

        self.ssl_verify = optional_args.get("ssl_verify", False)
        self.platform = "nxos"

    def open(self) -> None:
        pass

    def close(self) -> None:
        self.device = None

    def _send_command(self, command: str, raw_text: bool = False) -> Any:
        """
        Wrapper for NX-API show method.

        Allows more code sharing between NX-API and SSH.
        """
        assert self.device is not None, (
            "Call open() or use as a context manager before calling _send_command"
        )
        return self.device.show(command, raw_text=raw_text)

    def _send_command_list(self, commands: List[str]) -> List[Any]:
        assert self.device is not None, (
            "Call open() or use as a context manager before running _send_command_list"
        )
        return self.device.config_list(commands)

    def _send_config(self, commands: Union[str, List]) -> List[str]:
        assert self.device is not None, (
            "Call open() or use as a context manager before running _send_config"
        )
        if isinstance(commands, str):
            # Has to be a list generator and not generator expression (not JSON serializable)
            commands = [command for command in commands.splitlines() if command]
        return self.device.config_list(commands)

    @staticmethod
    def _compute_timestamp(stupid_cisco_output: str) -> float:
        """
        Some fields such `uptime` are returned as: 23week(s) 3day(s)
        This method will determine the epoch of the event.
        e.g.: 23week(s) 3day(s) -> 1462248287
        """
        if not stupid_cisco_output or stupid_cisco_output == "never":
            return -1.0

        if "(s)" in stupid_cisco_output:
            pass
        elif ":" in stupid_cisco_output:
            stupid_cisco_output = stupid_cisco_output.replace(":", "hour(s) ", 1)
            stupid_cisco_output = stupid_cisco_output.replace(":", "minute(s) ", 1)
            stupid_cisco_output += "second(s)"
        else:
            stupid_cisco_output = stupid_cisco_output.replace("d", "day(s) ")
            stupid_cisco_output = stupid_cisco_output.replace("h", "hour(s)")

        things: Dict[str, Dict[str, Union[int, float]]] = {
            "second(s)": {"weight": 1},
            "minute(s)": {"weight": 60},
            "hour(s)": {"weight": 3600},
            "day(s)": {"weight": 24 * 3600},
            "week(s)": {"weight": 7 * 24 * 3600},
            "year(s)": {"weight": 365.25 * 24 * 3600},
        }

        things_keys = things.keys()
        for part in stupid_cisco_output.split():
            for key in things_keys:
                if key in part:
                    things[key]["count"] = napalm.base.helpers.convert(int, part.replace(key, ""))

        delta = sum([det.get("count", 0) * det["weight"] for det in things.values()])
        return time.time() - delta

    def is_alive(self) -> models.AliveDict:
        if self.device:
            return {"is_alive": True}
        else:
            return {"is_alive": False}

    def _copy_run_start(self) -> None:
        assert self.device is not None, (
            "Call open() or use as a context manager before calling _copy_run_start"
        )
        results = self.device.save(filename="startup-config")
        if not results:
            msg = "Unable to save running-config to startup-config!"
            raise CommandErrorException(msg)

    def _load_cfg_from_checkpoint(self) -> None:
        commands = [
            "terminal dont-ask",
            "rollback running-config file {}".format(self.candidate_cfg),
            "no terminal dont-ask",
        ]
        try:
            rollback_result = self._send_command_list(commands)
        except ConnectionError:
            # requests will raise an error with verbose warning output (don't fail on this).
            return

        # For nx-api a list is returned so extract the result associated with the
        # 'rollback' command.
        rollback_result = rollback_result[1]
        assert isinstance(rollback_result, dict)
        msg = rollback_result.get("msg", "")
        error_msg = True if rollback_result.get("error") else False

        if "Rollback failed." in msg or error_msg:
            if error_msg:
                rollback_error = rollback_result.get("error", "")
                msg += f"\nCLI Error: {rollback_error}"
            raise ReplaceConfigException(msg)

    def rollback(self) -> None:
        assert isinstance(self.device, NXOSDevice)
        if not self._check_file_exists(cfg_file=self.rollback_cfg):
            msg = f"Rollback file '{self.rollback_cfg}' does not exist on device."
            raise ReplaceConfigException(msg)
        self.device.rollback(self.rollback_cfg)
        self._copy_run_start()

    def get_facts(self) -> models.FactsDict:
        facts: models.FactsDict = {}  # type: ignore
        facts["vendor"] = "Cisco"

        show_inventory_table = self._get_command_table("show inventory", "TABLE_inv", "ROW_inv")
        if isinstance(show_inventory_table, dict):
            show_inventory_table = [show_inventory_table]

        facts["serial_number"] = None  # type: ignore

        for row in show_inventory_table:
            if row["name"] == '"Chassis"' or row["name"] == "Chassis":
                facts["serial_number"] = row.get("serialnum", "")
                break

        show_version = self._send_command("show version")
        show_version = cast(Dict[str, str], show_version)
        facts["model"] = show_version.get("chassis_id", "")
        facts["hostname"] = show_version.get("host_name", "")
        facts["os_version"] = show_version.get(
            "sys_ver_str", show_version.get("kickstart_ver_str", "")
        )

        uptime_days = int(show_version.get("kern_uptm_days", 0))
        uptime_hours = int(show_version.get("kern_uptm_hrs", 0))
        uptime_mins = int(show_version.get("kern_uptm_mins", 0))
        uptime_secs = int(show_version.get("kern_uptm_secs", 0))

        uptime = 0
        uptime += uptime_days * 24 * 60 * 60
        uptime += uptime_hours * 60 * 60
        uptime += uptime_mins * 60
        uptime += uptime_secs

        facts["uptime"] = float(uptime)

        iface_cmd = "show interface"
        interfaces_out = self._send_command(iface_cmd)
        interfaces_body = interfaces_out["TABLE_interface"]["ROW_interface"]
        interface_list = [intf_data["interface"] for intf_data in interfaces_body]
        facts["interface_list"] = interface_list

        hostname_cmd = "show hostname"
        hostname = self._send_command(hostname_cmd).get("hostname")
        if hostname:
            facts["fqdn"] = hostname

        return facts

    def get_interfaces(self) -> Dict[str, models.InterfaceDict]:
        interfaces: Dict[str, models.InterfaceDict] = {}
        iface_cmd = "show interface"
        interfaces_out = self._send_command(iface_cmd)
        interfaces_body = interfaces_out["TABLE_interface"]["ROW_interface"]

        for interface_details in interfaces_body:
            assert isinstance(interface_details, dict)
            interface_name = interface_details.get("interface")
            assert isinstance(interface_name, str)

            if interface_details.get("eth_mtu"):
                interface_mtu = int(interface_details["eth_mtu"])
            elif interface_details.get("svi_mtu"):
                interface_mtu = int(interface_details["svi_mtu"])
            else:
                interface_mtu = 0

            # Earlier version of Nexus returned a list for 'eth_bw' (observed on 7.1(0)N1(1a))
            if interface_details.get("eth_bw"):
                interface_speed = interface_details["eth_bw"]
            elif interface_details.get("svi_bw"):
                interface_speed = interface_details["svi_bw"]
            else:
                interface_speed = 0
            if isinstance(interface_speed, list):
                interface_speed = interface_speed[0]
            interface_speed = float(float(interface_speed) / 1000.0)

            if "admin_state" in interface_details:
                is_up = interface_details.get("admin_state", "") == "up"
            elif "svi_admin_state" in interface_details:
                is_up = interface_details.get("svi_admin_state", "") == "up"
            else:
                is_up = interface_details.get("state", "") == "up"
            if interface_details.get("eth_hw_addr"):
                mac_address = interface_details["eth_hw_addr"]
            elif interface_details.get("svi_mac"):
                mac_address = interface_details["svi_mac"].strip()
            else:
                mac_address = None

            svi_desc = interface_details.get("svi_desc", "")
            assert isinstance(svi_desc, str)
            desc = interface_details.get("desc", svi_desc)
            assert isinstance(desc, str)
            desc = desc.strip('"')
            interfaces[interface_name] = {
                "is_up": is_up,
                "is_enabled": (
                    interface_details.get("state") == "up"
                    or interface_details.get("svi_admin_state") == "up"
                ),
                "description": desc,
                "last_flapped": self._compute_timestamp(
                    interface_details.get("eth_link_flapped", "")
                ),
                "speed": interface_speed,
                "mtu": interface_mtu,
                "mac_address": napalm.base.helpers.convert(napalm.base.helpers.mac, mac_address),
            }
        return interfaces

    def get_bgp_neighbors(self) -> Dict[str, models.BGPStateNeighborsPerVRFDict]:
        pass

    def cli(
        self, commands: List[str], encoding: str = "text"
    ) -> Dict[str, Union[str, Dict[str, Any]]]:
        if encoding not in ("text",):
            raise NotImplementedError("%s is not a supported encoding" % encoding)
        cli_output: Dict[str, Union[str, Dict[str, Any]]] = {}
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            command_output = self._send_command(command, raw_text=True)
            cli_output[str(command)] = command_output
        return cli_output

    def get_arp_table(self, vrf: str = "") -> List[models.ARPTableDict]:
        pass

    def _filter_ntp_table(self, peer_type: str) -> List[str]:
        pass

    def get_ntp_peers(self) -> Dict[str, models.NTPPeerDict]:
        pass

    def get_ntp_servers(self) -> Dict[str, models.NTPServerDict]:
        pass

    def get_ntp_stats(self) -> List[models.NTPStats]:
        pass

    def get_interfaces_ip(self) -> Dict[str, models.InterfacesIPDict]:
        pass

    def get_mac_address_table(self) -> List[models.MACAdressTable]:
        pass

    def get_snmp_information(self) -> models.SNMPDict:
        pass

    def get_users(self) -> Dict[str, models.UsersDict]:
        pass

    def get_network_instances(self, name: str = "") -> Dict[str, models.NetworkInstanceDict]:
        """get_network_instances implementation for NX-OS"""
        pass

    def get_environment(self) -> models.EnvironmentDict:
        pass

    def get_vlans(self) -> Dict[str, models.VlanDict]:
        pass
