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

"""
Napalm driver for Arista EOS.

Read napalm.readthedocs.org for more information.
"""

# std libs
import re
import time
import importlib
import inspect
import ipaddress
import json
import socket

from datetime import datetime
from collections import defaultdict

# third party libs
import pyeapi
from pyeapi.eapilib import ConnectionError, EapiConnection
from netmiko import ConfigInvalidException
from typing import Dict

# NAPALM base
import napalm.base.helpers
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.base import NetworkDriver, models
from napalm.base.utils import string_parsers
from napalm.base.exceptions import (
    CommitError,
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
    SessionLockedException,
    CommandErrorException,
    UnsupportedVersion,
)
from napalm.eos.constants import LLDP_CAPAB_TRANFORM_TABLE
from napalm.eos.utils.versions import EOSVersion
import napalm.base.constants as c

# local modules
# here add local imports
# e.g. import napalm.eos.helpers etc.


class EOSDriver(NetworkDriver):
    """Napalm driver for Arista EOS."""

    SUPPORTED_OC_MODELS = []

    HEREDOC_COMMANDS = [
        ("banner login", 1),
        ("banner motd", 1),
        ("comment", 1),
        ("protocol https certificate", 2),
    ]

    _RE_BGP_INFO = re.compile(r"BGP neighbor is (?P<neighbor>.*?), remote AS (?P<as>.*?), .*")  # noqa
    _RE_BGP_RID_INFO = re.compile(
        r".*BGP version 4, remote router ID (?P<rid>.*?), VRF (?P<vrf>.*?)$"
    )  # noqa
    _RE_BGP_DESC = re.compile(r"\s+Description: (?P<description>.*?)$")
    _RE_BGP_LOCAL = re.compile(r"Local AS is (?P<as>.*?),.*")
    _RE_BGP_PREFIX = re.compile(
        r"(\s*?)(?P<af>IPv[46]) (Unicast|6PE):\s*(?P<sent>\d+)\s*(?P<received>\d+)"
    )  # noqa
    _RE_SNMP_COMM = re.compile(
        r"""^snmp-server\s+community\s+(?P<community>\S+)
                                (\s+view\s+(?P<view>\S+))?(\s+(?P<access>ro|rw)?)
                                (\s+ipv6\s+(?P<v6_acl>\S+))?(\s+(?P<v4_acl>\S+))?$""",
        re.VERBOSE,
    )

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize EOS Driver.

        Optional args:
            * lock_disable (True/False): force configuration lock to be disabled (for external lock
                management).
            * force_cfg_session_invalid (True/False): force invalidation of the config session
                in case of failure.
            * enable_password (True/False): Enable password for privilege elevation
            * eos_autoComplete (True/False): Allow for shortening of cli commands
            * transport (string): transport, eos_transport is a fallback for compatibility.
                - ssh (uses Netmiko)
                - socket
                - http_local
                - http
                - https
                - https_certs
                - A subclass of EapiConnection
                - a string that identifies a module and class that is a subclass of EapiConnection
                (from: https://github.com/arista-eosplus/pyeapi/blob/develop/pyeapi/client.py#L115)

                transport is the preferred method
            * eos_transport (string): pyeapi transport, defaults to https
                eos_transport for backwards compatibility

        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_session = None
        self.locked = False

        self.platform = "eos"
        self.profile = [self.platform]
        self.optional_args = optional_args or {}

        self.enablepwd = self.optional_args.pop("enable_password", "")
        force_no_enable = self.optional_args.pop("force_no_enable", False)
        self.send_enable = not force_no_enable
        self.eos_autoComplete = self.optional_args.pop("eos_autoComplete", None)

        # Define locking method
        self.lock_disable = self.optional_args.pop("lock_disable", False)

        self.force_cfg_session_invalid = self.optional_args.pop("force_cfg_session_invalid", False)

        # eos_transport is there for backwards compatibility, transport is the preferred method
        transport = self.optional_args.get(
            "transport", self.optional_args.get("eos_transport", "https")
        )
        self.transport = transport

        if transport == "ssh":
            self._process_optional_args_ssh(self.optional_args)
        else:
            self._process_optional_args_eapi(self.optional_args)

    def _process_optional_args_ssh(self, optional_args):
        pass

    def _process_optional_args_eapi(self, optional_args):
        # Parse pyeapi transport class
        pass

    def _parse_transport(self, transport):
        pass

    def open(self):
        """Implementation of NAPALM method open."""
        pass

    def close(self):
        """Implementation of NAPALM method close."""
        self.discard_config()
        if self.transport == "ssh":
            self._netmiko_close()
        elif hasattr(self.device.connection, "close") and callable(self.device.connection.close):
            self.device.connection.close()

    def is_alive(self):
        if self.transport == "ssh":
            null = chr(0)
            if self.device is None:
                return {"is_alive": False}
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                return {"is_alive": self.device.remote_conn.transport.is_active()}
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                return {"is_alive": False}

        if hasattr(self.device.connection, "is_alive") and callable(
            self.device.connection.is_alive
        ):
            return self.device.connection.is_alive()
        return {"is_alive": True}  # always true as eAPI is HTTP-based

    def _run_commands(self, commands, **kwargs):
        if self.transport == "ssh":
            ret = []
            for command in commands:
                if kwargs.get("encoding") == "text":
                    cmd_output = self._netmiko_device.send_command(command).replace(
                        "% Invalid input", ""
                    )
                    ret.append({"output": cmd_output})
                    continue

                cmd_pipe = command + " | json"
                cmd_txt = self._netmiko_device.send_command(cmd_pipe)
                try:
                    cmd_json = json.loads(cmd_txt)
                except json.decoder.JSONDecodeError:
                    cmd_json = {}
                ret.append(cmd_json)
            return ret
        else:
            kwargs.setdefault("send_enable", self.send_enable)
            return self.device.run_commands(commands, **kwargs)

    def _obtain_lock(self, wait_time=None):
        """
        EOS internally creates config sessions when using commit-confirm.

        This can cause issues obtaining the configuration lock:

        cfg-2034--574620864-0 completed
        cfg-2034--574620864-1 pending
        """
        pass

    def _lock(self):
        pass

    def _get_pending_commits(self):
        """
        Return a dictionary of configuration sessions with pending commit confirms and
        corresponding time when confirm needs to happen by (rounded to nearest second).

        Example:
        {'napalm_607123': 522}
        """
        config_sessions = self._run_commands(["show configuration sessions detail"])
        # Arista reports the commitBy time relative to uptime of the box... :-(
        uptime = self._run_commands(["show version"])
        uptime = uptime[0].get("uptime", -1)

        pending_commits = {}
        # Syntax change >EOS 4.32
        if "commitTimerSessionName" in config_sessions[0]:
            config_sessions = config_sessions[0]
            session_name = config_sessions["commitTimerSessionName"]
            commit_by = config_sessions["commitTimerExpireTime"]
            if commit_by == -1 or uptime == -1:
                pending_commits[session_name] = -1
            elif uptime >= commit_by:
                pending_commits[session_name] = -1
            else:
                confirm_by_seconds = commit_by - uptime
                pending_commits[session_name] = round(confirm_by_seconds)
        else:
            config_sessions = config_sessions[0]["sessions"]
            for session_name, session_dict in config_sessions.items():
                if "pendingCommitTimer" in session_dict["state"]:
                    commit_by = session_dict.get("commitBy", -1)
                    # Set to -1 if something went wrong in the calculation.
                    if commit_by == -1 or uptime == -1:
                        pending_commits[session_name] = -1
                    elif uptime >= commit_by:
                        pending_commits[session_name] = -1
                    else:
                        confirm_by_seconds = commit_by - uptime
                        pending_commits[session_name] = round(confirm_by_seconds)

        return pending_commits

    @staticmethod
    def _multiline_convert(config, start="banner login", end="EOF", depth=1):
        """Converts running-config HEREDOC into EAPI JSON dict"""
        pass

    @staticmethod
    def _mode_comment_convert(commands):
        """
        EOS has the concept of multi-line mode comments, shown in the running-config
        as being inside a config stanza (router bgp, ACL definition, etc) and beginning
        with the normal level of spaces and '!!', followed by comments.

        Unfortunately, pyeapi does not accept mode comments in this format, and have to be
        converted to a specific type of pyeapi call that accepts multi-line input

        Copy the config list into a new return list, converting consecutive lines starting with
        "!!" into a single multiline comment command

        :param commands: List of commands to be sent to pyeapi
        :return: Converted list of commands to be sent to pyeapi
        """
        pass

    def _load_config(self, filename=None, config=None, replace=True):
        pass

    def load_replace_candidate(self, filename=None, config=None):
        """Implementation of NAPALM method load_replace_candidate."""
        pass

    def load_merge_candidate(self, filename=None, config=None):
        """Implementation of NAPALM method load_merge_candidate."""
        pass

    def compare_config(self):
        """Implementation of NAPALM method compare_config."""
        if self.config_session is None:
            return ""
        else:
            commands = ["show session-config named %s diffs" % self.config_session]
            result = self._run_commands(commands, encoding="text")[0]["output"]

            result = "\n".join(result.splitlines()[2:])

            return result.strip()

    def commit_config(self, message="", revert_in=None):
        """Implementation of NAPALM method commit_config."""

        if message:
            raise NotImplementedError("Commit message not implemented for this platform")

        if revert_in is not None:
            if self.has_pending_commit():
                raise CommitError("Pending commit confirm already in process!")

            commands = [
                "copy startup-config flash:rollback-0",
                "configure session {} commit timer {}".format(
                    self.config_session,
                    time.strftime("%H:%M:%S", time.gmtime(revert_in)),
                ),
            ]
            self._run_commands(commands, encoding="text")
        else:
            commands = [
                "copy startup-config flash:rollback-0",
                "configure session {} commit".format(self.config_session),
                "write memory",
            ]

            self._run_commands(commands, encoding="text")
            self.config_session = None

    def has_pending_commit(self):
        """Boolean indicating if there is a commit-confirm in process."""
        pending_commits = self._get_pending_commits()
        # pending_commits will return an empty dict, if there are no commit-confirms pending.
        return bool(pending_commits)

    def confirm_commit(self):
        """Send final commit to confirm an in-proces commit that requires confirmation."""
        pass

    def discard_config(self):
        """Implementation of NAPALM method discard_config."""
        if self.config_session is not None:
            try:
                commands = [f"configure session {self.config_session} abort"]
                self._run_commands(commands, encoding="text")
            except Exception:
                # If discard fails, you might want to invalidate the config_session (esp. Salt)
                # The config_session in EOS is used as the config lock.
                if self.force_cfg_session_invalid:
                    self.config_session = None
                raise
            self.config_session = None

    def rollback(self):
        """Implementation of NAPALM method rollback."""

        # Commit-confirm check and abort
        pending_commits = self._get_pending_commits()
        if pending_commits:
            # Make sure pending commit matches self.config_session
            if pending_commits.get(self.config_session):
                commands = [
                    "configure session {} abort".format(self.config_session),
                    "write memory",
                ]
            else:
                msg = "Current config session not found as pending commit-confirm"
                raise CommitError(msg)

        # Standard rollback
        else:
            commands = ["configure replace flash:rollback-0", "write memory"]

        self._run_commands(commands, encoding="text")
        self.config_session = None

    def get_facts(self):
        """Implementation of NAPALM method get_facts."""
        commands = ["show version", "show hostname", "show interfaces"]

        result = self._run_commands(commands)

        version = result[0]
        hostname = result[1]
        interfaces_dict = result[2]["interfaces"]

        uptime = time.time() - version["bootupTimestamp"]

        interfaces = [i for i in interfaces_dict.keys() if "." not in i]
        interfaces = string_parsers.sorted_nicely(interfaces)

        return {
            "hostname": hostname["hostname"],
            "fqdn": hostname["fqdn"],
            "vendor": "Arista",
            "model": version["modelName"],
            "serial_number": version["serialNumber"],
            "os_version": version["internalVersion"],
            "uptime": float(uptime),
            "interface_list": interfaces,
        }

    def get_interfaces(self):
        commands = ["show interfaces"]
        output = self._run_commands(commands)[0]

        interfaces = {}

        for interface, values in output["interfaces"].items():
            interfaces[interface] = {}

            if values["lineProtocolStatus"] == "up":
                interfaces[interface]["is_up"] = True
                interfaces[interface]["is_enabled"] = True
            else:
                interfaces[interface]["is_up"] = False
                if values["interfaceStatus"] == "disabled":
                    interfaces[interface]["is_enabled"] = False
                else:
                    interfaces[interface]["is_enabled"] = True

            interfaces[interface]["description"] = values["description"]

            interfaces[interface]["last_flapped"] = values.pop("lastStatusChangeTimestamp", -1.0)

            interfaces[interface]["mtu"] = int(values["mtu"])
            #            interfaces[interface]["speed"] = float(values["bandwidth"] * 1e-6)
            interfaces[interface]["speed"] = float(values["bandwidth"] / 1000000.0)
            interfaces[interface]["mac_address"] = napalm.base.helpers.convert(
                napalm.base.helpers.mac, values.pop("physicalAddress", "")
            )

        return interfaces

    def get_lldp_neighbors(self):
        pass

    def get_interfaces_counters(self):
        pass

    def get_bgp_neighbors(self) -> Dict[str, models.BGPStateNeighborsPerVRFDict]:
        pass

    def get_environment(self):
        pass

    def _transform_lldp_capab(self, capabilities):
        pass

    def get_lldp_neighbors_detail(self, interface=""):
        pass

    def cli(self, commands, encoding="text"):
        if encoding not in ("text", "json"):
            raise NotImplementedError("%s is not a supported encoding" % encoding)
        cli_output = {}

        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            try:
                result = self._run_commands([command], encoding=encoding)
                if encoding == "text":
                    cli_output[str(command)] = result[0]["output"]
                else:
                    cli_output[str(command)] = result[0]
                # not quite fair to not exploit rum_commands
                # but at least can have better control to point to wrong command in case of failure
            except pyeapi.eapilib.CommandError:
                # for sure this command failed
                cli_output[str(command)] = 'Invalid command: "{cmd}"'.format(cmd=command)
                raise CommandErrorException(str(cli_output))
            except Exception as e:
                # something bad happened
                msg = 'Unable to execute command "{cmd}": {err}'.format(cmd=command, err=e)
                cli_output[str(command)] = msg
                raise CommandErrorException(str(cli_output))

        return cli_output

    def get_bgp_config(self, group="", neighbor=""):
        """Implementation of NAPALM method get_bgp_config."""
        pass

    def get_arp_table(self, vrf=""):
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
        """get_snmp_information() for EOS.  Re-written to not use TextFSM"""
        pass

    def get_users(self):
        pass

    def traceroute(
        self,
        destination,
        source=c.TRACEROUTE_SOURCE,
        ttl=c.TRACEROUTE_TTL,
        timeout=c.TRACEROUTE_TIMEOUT,
        vrf=c.TRACEROUTE_VRF,
    ):
        pass

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Implementation of get_bgp_neighbors_detail"""
        pass

    def get_optics(self):
        pass

    def get_config(self, retrieve="all", full=False, sanitized=False, format="text"):
        """get_config implementation for EOS."""
        get_startup = retrieve == "all" or retrieve == "startup"
        get_running = retrieve == "all" or retrieve == "running"
        get_candidate = (retrieve == "all" or retrieve == "candidate") and self.config_session

        # EOS only supports "all" on "show run"
        run_full = " all" if full else ""
        run_sanitized = " sanitized" if sanitized else ""

        if retrieve == "all":
            commands = [
                "show startup-config",
                "show running-config{0}{1}".format(run_full, run_sanitized),
            ]

            if self.config_session:
                commands.append(
                    "show session-config named {0}{1}".format(self.config_session, run_sanitized)
                )

            output = self._run_commands(commands, encoding="text")
            startup_cfg = str(output[0]["output"]) if get_startup else ""
            if sanitized and startup_cfg:
                startup_cfg = napalm.base.helpers.sanitize_config(
                    startup_cfg, c.EOS_SANITIZE_FILTERS
                )
            return {
                "startup": startup_cfg,
                "running": str(output[1]["output"]) if get_running else "",
                "candidate": str(output[2]["output"]) if get_candidate else "",
            }
        elif get_startup or get_running:
            if retrieve == "running":
                commands = ["show {}-config{}{}".format(retrieve, run_full, run_sanitized)]
            elif retrieve == "startup":
                commands = ["show {}-config".format(retrieve)]
            output = self._run_commands(commands, encoding="text")
            startup_cfg = str(output[0]["output"]) if get_startup else ""
            if sanitized and get_startup and startup_cfg:
                startup_cfg = napalm.base.helpers.sanitize_config(
                    startup_cfg, c.EOS_SANITIZE_FILTERS
                )
            return {
                "startup": startup_cfg,
                "running": str(output[0]["output"]) if get_running else "",
                "candidate": "",
            }
        elif get_candidate:
            commands = ["show session-config named {}{}".format(self.config_session, run_sanitized)]
            output = self._run_commands(commands, encoding="text")
            return {"startup": "", "running": "", "candidate": str(output[0]["output"])}
        elif retrieve == "candidate":
            # If we get here it means that we want the candidate but there is none.
            return {"startup": "", "running": "", "candidate": ""}
        else:
            raise Exception("Wrong retrieve filter: {}".format(retrieve))

    def _show_vrf_json(self):
        pass

    def _show_vrf_text(self):
        pass

    def _show_vrf(self):
        pass

    def _get_vrfs(self):
        pass

    def get_network_instances(self, name=""):
        """get_network_instances implementation for EOS."""
        pass

    def ping(
        self,
        destination,
        source=c.PING_SOURCE,
        ttl=c.PING_TTL,
        timeout=c.PING_TIMEOUT,
        size=c.PING_SIZE,
        count=c.PING_COUNT,
        vrf=c.PING_VRF,
        source_interface=c.PING_SOURCE_INTERFACE,
    ):
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

    def get_vlans(self):
        pass
