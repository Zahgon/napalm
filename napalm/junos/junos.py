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

"""Driver for JunOS devices."""

# import stdlib
import re
import json
import logging
import collections
from copy import deepcopy
from collections import OrderedDict, defaultdict

# import third party lib
from lxml.builder import E
from lxml import etree

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import RpcError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import RpcTimeoutError
from jnpr.junos.exception import ConnectTimeoutError
from jnpr.junos.exception import ProbeError
from jnpr.junos.exception import LockError as JnprLockError
from jnpr.junos.exception import UnlockError as JnrpUnlockError

# import NAPALM Base
import napalm.base.helpers
from napalm.base.base import NetworkDriver
from napalm.junos import constants as C
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import CommandErrorException
from napalm.base.exceptions import ReplaceConfigException
from napalm.base.exceptions import CommandTimeoutException
from napalm.base.exceptions import LockError
from napalm.base.exceptions import UnlockError
from napalm.base.exceptions import CommitConfirmException

# import local modules
from napalm.junos.utils import junos_views

log = logging.getLogger(__file__)


class JunOSDriver(NetworkDriver):
    """JunOSDriver class - inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialise JunOS driver.

        Optional args:
            * config_lock (True/False): lock configuration DB after the connection is established.
            * lock_disable (True/False): force configuration lock to be disabled (for external lock
                management).
            * config_private (True/False): juniper configure private command, no DB locking
            * port (int): custom port
            * key_file (string): SSH key file path
            * keepalive (int): Keepalive interval
            * ignore_warning (boolean): not generate warning exceptions
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_replace = False
        self.locked = False

        # Get optional arguments
        if optional_args is None:
            optional_args = {}

        self.port = optional_args.get("port", 22)
        self.key_file = optional_args.get("key_file", None)
        self.keepalive = optional_args.get("keepalive", 30)
        self.ssh_config_file = optional_args.get("ssh_config_file", None)
        self.ignore_warning = optional_args.get("ignore_warning", False)
        self.auto_probe = optional_args.get("auto_probe", 0)
        self.huge_tree = optional_args.get("huge_tree", False)

        # Define locking method
        self.lock_disable = optional_args.get("lock_disable", False)
        self.session_config_lock = optional_args.get("config_lock", False)
        self.config_private = optional_args.get("config_private", False)

        # Junos driver specific options
        self.junos_config_database = optional_args.get("junos_config_database", "committed")
        self.junos_config_inheritance = optional_args.get("junos_config_inherit", "inherit")
        self.junos_config_groups = optional_args.get("junos_config_groups", "groups")
        self.junos_config_options = {
            "database": self.junos_config_database,
            "inherit": self.junos_config_inheritance,
            "groups": self.junos_config_groups,
        }
        self.junos_config_options = optional_args.get(
            "junos_config_options", self.junos_config_options
        )

        if self.key_file:
            self.device = Device(
                hostname,
                user=username,
                password=password,
                ssh_private_key_file=self.key_file,
                ssh_config=self.ssh_config_file,
                port=self.port,
                huge_tree=self.huge_tree,
            )
        else:
            self.device = Device(
                hostname,
                user=username,
                password=password,
                port=self.port,
                ssh_config=self.ssh_config_file,
                huge_tree=self.huge_tree,
            )

        self.platform = "junos"
        self.profile = [self.platform]

    def open(self):
        """Open the connection with the device."""
        pass

    def close(self):
        """Close the connection."""
        if not self.lock_disable and self.session_config_lock:
            self._unlock()
        self.device.close()

    def _lock(self):
        """Lock the config DB."""
        pass

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            try:
                self.device.cu.unlock()
                self.locked = False
            except JnrpUnlockError as jue:
                raise UnlockError(jue)

    def _rpc(self, get, child=None, **kwargs):
        """
        This allows you to construct an arbitrary RPC call to retrieve common stuff. For example:
        Configuration:  get: "<get-configuration/>"
        Interface information:  get: "<get-interface-information/>"
        A particular interface information:
              get: "<get-interface-information/>"
              child: "<interface-name>ge-0/0/0</interface-name>"
        """
        pass

    def is_alive(self):
        # evaluate the state of the underlying SSH connection
        # and also the NETCONF status from PyEZ
        return {
            "is_alive": self.device._conn._session.transport.is_active() and self.device.connected
        }

    @staticmethod
    def _is_json_format(config):
        pass

    def _detect_config_format(self, config):
        pass

    def _load_candidate(self, filename, config, overwrite):
        pass

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        pass

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        pass

    def compare_config(self):
        """Compare candidate config with running."""
        diff = self.device.cu.diff(ignore_warning=self.ignore_warning)

        if diff is None:
            return ""
        else:
            return diff.strip()

    def commit_config(self, message="", revert_in=None):
        """Commit configuration."""
        commit_args = {}
        if revert_in is not None:
            if revert_in % 60 != 0:
                if not self.lock_disable and not self.session_config_lock:
                    self._unlock()
                raise CommitConfirmException(
                    "For Junos devices revert_in must be a multiple of 60 (60, 120, 180...)"
                )
            else:
                juniper_confirm_time = int(revert_in / 60)
                commit_args["confirm"] = juniper_confirm_time

        if message:
            commit_args["comment"] = message
        self.device.cu.commit(ignore_warning=self.ignore_warning, **commit_args)

        if not self.lock_disable and not self.session_config_lock:
            self._unlock()

        if self.config_private:
            self.device.rpc.close_configuration()

    def has_pending_commit(self):
        """Boolean indicating if there is a commit-confirm in process."""
        pending_commit = self._get_pending_commits()
        if pending_commit:
            return True
        else:
            return False

    def _get_pending_commits(self):
        """
        Return a dictionary of commit sequences with pending commit confirms and
        corresponding time when confirm needs to happen by. This is converted to seconds
        since Juniper reports this in minutes.

        Example:
        {'re0-1616554286-559': 522}

        Will only report on a single commit (the most recent one).

        Will return an empty dictionary if there is no pending commit-confirms.
        """
        # show system commit revision detail
        # Command introduced in Junos OS Release 14.1
        try:
            pending_commit = self.device.rpc.get_commit_revision_information(detail=True)
        except RpcError:
            msg = "Using commit-confirm with NAPALM requires Junos OS >= 14.1"
            raise CommitConfirmException(msg)

        commit_time_element = pending_commit.find("./date-time")
        commit_time = int(commit_time_element.attrib["seconds"])

        commit_revision_element = pending_commit.find("./revision")
        commit_revision = commit_revision_element.text
        commit_comment_element = pending_commit.find("./comment")
        if commit_comment_element is None:
            # No commit comment means no commit-confirm
            return {}
        else:
            commit_comment = commit_comment_element.text

        sys_uptime_info = self.device.rpc.get_system_uptime_information()
        current_time_element = sys_uptime_info.find(".//current-time/date-time")
        current_time = int(current_time_element.attrib["seconds"])

        # Msg from Jnpr: 'commit confirmed, rollback in 5mins'
        if "commit confirmed" in commit_comment and "rollback in" in commit_comment:
            match = re.search(r"rollback in (\d+)mins", commit_comment)
            if match:
                confirm_time = match.group(1)
                confirm_time_seconds = int(confirm_time) * 60
                elapsed_time = current_time - commit_time
                confirm_time_remaining = confirm_time_seconds - elapsed_time
                if confirm_time_remaining <= 0:
                    confirm_time_remaining = 0

                return {commit_revision: confirm_time_remaining}

        return {}

    def confirm_commit(self):
        """Send final commit to confirm an in-proces commit that requires confirmation."""
        pass

    def discard_config(self):
        """Discard changes (rollback 0)."""
        self.device.cu.rollback(rb_id=0, ignore_warning=self.ignore_warning)
        if not self.lock_disable and not self.session_config_lock:
            self._unlock()
        if self.config_private:
            self.device.rpc.close_configuration()

    def rollback(self):
        """Rollback to previous commit."""
        self.device.cu.rollback(rb_id=1)
        self.commit_config()

    def get_facts(self):
        """Return facts of the device."""
        output = self.device.facts

        uptime = self.device.uptime or -1

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()
        interface_list = interfaces.keys()

        return {
            "vendor": "Juniper",
            "model": str(output["model"]),
            "serial_number": str(output["serialnumber"]),
            "os_version": str(output["version"]),
            "hostname": str(output["hostname"]),
            "fqdn": str(output["fqdn"]),
            "uptime": float(uptime),
            "interface_list": interface_list,
        }

    def get_interfaces(self):
        """Return interfaces details."""
        result = {}

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()
        interfaces_logical = junos_views.junos_logical_iface_table(self.device)
        interfaces_logical.get()

        # convert all the tuples to our pre-defined dict structure
        def _convert_to_dict(interfaces):
            # calling .items() here wont work.
            # The dictionary values will end up being tuples instead of dictionaries
            interfaces = dict(interfaces)
            for iface, iface_data in interfaces.items():
                result[iface] = {
                    "is_up": iface_data["is_up"],
                    # For physical interfaces <admin-status> will always be there, so just
                    # return the value interfaces[iface]['is_enabled']
                    # For logical interfaces if <iff-down> is present interface is disabled,
                    # otherwise interface is enabled
                    "is_enabled": (
                        True if iface_data["is_enabled"] is None else iface_data["is_enabled"]
                    ),
                    "description": (iface_data["description"] or ""),
                    "last_flapped": float((iface_data["last_flapped"] or -1)),
                    "mac_address": napalm.base.helpers.convert(
                        napalm.base.helpers.mac,
                        iface_data["mac_address"],
                        str(iface_data["mac_address"]),
                    ),
                    "speed": -1.0,
                    "mtu": 0,
                }
                # result[iface]['last_flapped'] = float(result[iface]['last_flapped'])

                match_mtu = re.search(r"(\w+)", str(iface_data["mtu"]) or "")
                mtu = napalm.base.helpers.convert(int, match_mtu.group(0), 0)
                result[iface]["mtu"] = mtu
                match = re.search(r"(\d+|[Aa]uto)(\w*)", iface_data["speed"] or "")
                if match and match.group(1).lower() == "auto":
                    match = re.search(r"(\d+)(\w*)", iface_data["negotiated_speed"] or "")
                if match is None:
                    continue
                speed_value = napalm.base.helpers.convert(float, match.group(1), -1.0)

                if speed_value == -1.0:
                    continue
                speed_unit = match.group(2)
                if speed_unit.lower() == "gbps":
                    speed_value *= 1000.0
                result[iface]["speed"] = speed_value

            return result

        result = _convert_to_dict(interfaces)
        result.update(_convert_to_dict(interfaces_logical))
        return result

    def get_interfaces_counters(self):
        """Return interfaces counters."""
        pass

    def get_environment(self):
        """Return environment details."""
        pass

    @staticmethod
    def _get_address_family(table, instance):
        """
        Function to derive address family from a junos table name.

        :params table: The name of the routing table
        :returns: address family
        """
        pass

    def _parse_route_stats(self, neighbor, instance):
        pass

    @staticmethod
    def _parse_value(value):
        pass

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""
        pass

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        pass

    def _transform_lldp_capab(self, capabilities):
        pass

    def get_lldp_neighbors_detail(self, interface=""):
        """Detailed view of the LLDP neighbors."""
        pass

    def cli(self, commands, encoding="text"):
        """Execute raw CLI commands and returns their output."""
        if encoding not in ("text", "json", "xml"):
            raise NotImplementedError("%s is not a supported encoding" % encoding)
        cli_output = {}

        def _count(txt, none):  # Second arg for consistency only. noqa
            """
            Return the exact output, as Junos displays
            e.g.:
            > show system processes extensive | match root | count
            Count: 113 lines
            """
            pass

        def _trim(txt, length):
            """
            Trim specified number of columns from start of line.
            """
            pass

        def _except(txt, pattern):
            """
            Show only text that does not match a pattern.
            """
            pass

        def _last(txt, length):
            """
            Display end of output only.
            """
            pass

        def _match(txt, pattern):
            """
            Show only text that matches a pattern.
            """
            pass

        def _find(txt, pattern):
            """
            Search for first occurrence of pattern.
            """
            pass

        def _process_pipe(cmd, txt):
            """
            Process CLI output from Juniper device that
            doesn't allow piping the output.
            """
            if txt is None:
                return txt
            _OF_MAP = OrderedDict()
            _OF_MAP["except"] = _except
            _OF_MAP["match"] = _match
            _OF_MAP["last"] = _last
            _OF_MAP["trim"] = _trim
            _OF_MAP["count"] = _count
            _OF_MAP["find"] = _find
            # the operations order matter in this case!
            exploded_cmd = cmd.split("|")
            pipe_oper_args = {}
            for pipe in exploded_cmd[1:]:
                exploded_pipe = pipe.split()
                pipe_oper = exploded_pipe[0]  # always there
                pipe_args = "".join(exploded_pipe[1:2])
                # will not throw error when there's no arg
                pipe_oper_args[pipe_oper] = pipe_args
            for oper in _OF_MAP.keys():
                # to make sure the operation sequence is correct
                if oper not in pipe_oper_args.keys():
                    continue
                txt = _OF_MAP[oper](txt, pipe_oper_args[oper])
            return txt

        if not isinstance(commands, list):
            raise TypeError("Please enter a valid list of commands!")
        _PIPE_BLACKLIST = ["save"]
        # Preprocessing to avoid forbidden commands
        for command in commands:
            exploded_cmd = command.split("|")
            command_safe_parts = []
            for pipe in exploded_cmd[1:]:
                exploded_pipe = pipe.split()
                pipe_oper = exploded_pipe[0]  # always there
                if pipe_oper in _PIPE_BLACKLIST:
                    continue
                pipe_args = "".join(exploded_pipe[1:2])
                safe_pipe = (
                    pipe_oper
                    if not pipe_args
                    else "{fun} {args}".format(fun=pipe_oper, args=pipe_args)
                )
                command_safe_parts.append(safe_pipe)
            safe_command = (
                exploded_cmd[0]
                if not command_safe_parts
                else "{base} | {pipes}".format(
                    base=exploded_cmd[0], pipes=" | ".join(command_safe_parts)
                )
            )
            raw_txt = self.device.cli(safe_command, warning=False, format=encoding)
            if isinstance(raw_txt, etree._Element):
                raw_txt = etree.tostring(raw_txt.getparent()).decode()
                cli_output[str(command)] = raw_txt
            else:
                cli_output[str(command)] = str(_process_pipe(command, raw_txt))
        return cli_output

    def get_bgp_config(self, group="", neighbor=""):
        """Return BGP configuration."""
        pass

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Detailed view of the BGP neighbors operational data."""
        pass

    def get_arp_table(self, vrf=""):
        """Return the ARP table."""
        pass

    def get_ipv6_neighbors_table(self):
        """Return the IPv6 neighbors table."""
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
        """Return route details to a specific destination, learned from a certain protocol."""
        pass

    def get_snmp_information(self):
        """Return the SNMP configuration."""
        pass

    def get_probes_config(self):
        """Return the configuration of the RPM probes."""
        pass

    def get_probes_results(self):
        """Return the results of the RPM probes."""
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

    def ping(
        self,
        destination,
        source=C.PING_SOURCE,
        ttl=C.PING_TTL,
        timeout=C.PING_TIMEOUT,
        size=C.PING_SIZE,
        count=C.PING_COUNT,
        vrf=C.PING_VRF,
        source_interface=C.PING_SOURCE_INTERFACE,
    ):
        pass

    def _get_root(self):
        """get root user password."""
        pass

    def get_users(self):
        """Return the configuration of the users."""
        pass

    def get_optics(self):
        """Return optics information."""
        pass

    def get_config(self, retrieve="all", full=False, sanitized=False, format="text"):
        rv = {"startup": "", "running": "", "candidate": ""}

        self.format = format
        options = {"format": self.format, "database": "candidate"}
        sanitize_strings = {
            r"^(\s+community\s+)\w+(;.*|\s+{.*)$": r"\1<removed>\2",
            r'^(.*)"\$\d\$\S+"(;.*)$': r"\1<removed>\2",
        }
        if retrieve in ("candidate", "all"):
            config = self.device.rpc.get_config(filter_xml=None, options=options)
            rv["candidate"] = str(config.text)
        if retrieve in ("running", "all"):
            options["database"] = "committed"
            config = self.device.rpc.get_config(filter_xml=None, options=options)
            rv["running"] = str(config.text)

        if sanitized:
            return napalm.base.helpers.sanitize_configs(rv, sanitize_strings)

        return rv

    def get_network_instances(self, name=""):
        pass

    def get_vlans(self):
        pass
