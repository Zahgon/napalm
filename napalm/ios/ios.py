"""NAPALM Cisco IOS Handler."""

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
import copy
import functools
import ipaddress
import os
import re
import socket
from netmiko._telnetlib import telnetlib
import tempfile
import uuid

from netmiko import FileTransfer, InLineTransfer

import napalm.base.constants as C
import napalm.base.helpers
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    ReplaceConfigException,
    MergeConfigException,
    ConnectionClosedException,
    CommandErrorException,
    CommitConfirmException,
)
from napalm.base.helpers import (
    transform_lldp_capab,
    textfsm_extractor,
    generate_regex_or,
    sanitize_configs,
)
from netaddr.core import AddrFormatError
from netutils.interface import (
    abbreviated_interface_name,
    canonical_interface_name,
    split_interface,
)
from napalm.base.netmiko_helpers import netmiko_args

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{0,39}::[0-9a-fA-F:]{0,39}"
IPV6_ADDR_REGEX_3 = (
    r"[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:"
    "[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}"
)
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = "(?:{}|{}|{})".format(IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3)

MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"
VLAN_REGEX = r"\d{1,4}"
INT_REGEX = r"(^\w{1,2}\d{1,3}/\d{1,2}|^\w{1,2}\d{1,3})"
RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_IPADDR_STRIP = re.compile(r"({})\n".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))

# Period needed for 32-bit AS Numbers
ASN_REGEX = r"[\d\.]+"

RE_IP_ROUTE_VIA_REGEX = re.compile(
    r"[ ]{2}([*| ])[ ](?P<ip>" + IP_ADDR_REGEX + r")"
    r"( [\(\)a-z\d\.]+)?(, from " + IP_ADDR_REGEX + r", "
    r"(?P<age>[\ddhwy:]+) ago)?(, via (?P<via>\S+))?"
)

RE_VRF_SIMPLE = re.compile(r"[ ]{2}(\S+)")
RE_VRF_ADVAN = re.compile(r"[ ]{2}(\S+)[ ]+[<> a-z:\d]+[ ]+([a-z\d,]+)")

RE_BGP_REMOTE_AS = re.compile(r"remote AS (" + ASN_REGEX + r")")
RE_BGP_AS_PATH = re.compile(r"^[ ]{2}([\d\(]([\d\) ]+)|Local)")

RE_RP_ROUTE = re.compile(r"Routing entry for (" + IP_ADDR_REGEX + r"\/\d+)")
RE_RP_FROM = re.compile(r"Known via \"([a-z]+)[ \"]")
RE_RP_VIA = re.compile(r"via (\S+)")
RE_RP_METRIC = re.compile(r"[ ]+Route metric is (\d+)")

IOS_COMMANDS = {"show_mac_address": ["show mac-address-table", "show mac address-table"]}

AFI_COMMAND_MAP = {
    "IPv4 Unicast": "ipv4 unicast",
    "IPv6 Unicast": "ipv6 unicast",
    "VPNv4 Unicast": "vpnv4 all",
    "VPNv6 Unicast": "vpnv6 unicast all",
    "IPv4 Multicast": "ipv4 multicast",
    "IPv6 Multicast": "ipv6 multicast",
    "L2VPN E-VPN": "l2vpn evpn",
    "MVPNv4 Unicast": "ipv4 mvpn all",
    "MVPNv6 Unicast": "ipv6 mvpn all",
    "VPNv4 Flowspec": "ipv4 flowspec",
    "VPNv6 Flowspec": "ipv6 flowspec",
}


class IOSDriver(NetworkDriver):
    """NAPALM Cisco IOS Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM Cisco IOS Handler."""
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.transport = optional_args.get("transport", "ssh")

        # Retrieve file names
        self.candidate_cfg = optional_args.get("candidate_cfg", "candidate_config.txt")
        self.merge_cfg = optional_args.get("merge_cfg", "merge_config.txt")
        self.rollback_cfg = optional_args.get("rollback_cfg", "rollback_config.txt")
        self.inline_transfer = optional_args.get("inline_transfer", False)
        if self.transport == "telnet":
            # Telnet only supports inline_transfer
            self.inline_transfer = True

        # None will cause autodetection of dest_file_system
        self._dest_file_system = optional_args.get("dest_file_system", None)
        self.auto_rollback_on_error = optional_args.get("auto_rollback_on_error", True)

        # Control automatic execution of 'file prompt quiet' for file operations
        self.auto_file_prompt = optional_args.get("auto_file_prompt", True)

        # Track whether 'file prompt quiet' has been changed by NAPALM.
        self.prompt_quiet_changed = False
        # Track whether 'file prompt quiet' is known to be configured
        self.prompt_quiet_configured = None

        self.netmiko_optional_args = netmiko_args(optional_args)

        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

        self.device = None
        self.config_replace = False

        self.platform = "ios"
        self.profile = [self.platform]
        self.use_canonical_interface = optional_args.get("canonical_int", False)
        self.force_no_enable = optional_args.get("force_no_enable", False)

    def open(self):
        """Open a connection to the device."""
        pass

    def _discover_file_system(self):
        pass

    def close(self):
        """Close the connection to the device and do the necessary cleanup."""

        # Return file prompt quiet to the original state
        if self.auto_file_prompt and self.prompt_quiet_changed is True:
            self.device.send_config_set(["no file prompt quiet"])
            self.prompt_quiet_changed = False
            self.prompt_quiet_configured = False
        self._netmiko_close()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().

        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return self._send_command_postprocess(output)
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        null = chr(0)
        if self.device is None:
            return {"is_alive": False}
        if self.transport == "telnet":
            try:
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return {"is_alive": True}
            except UnicodeDecodeError:
                # Netmiko logging bug (remove after Netmiko >= 1.4.3)
                return {"is_alive": True}
            except AttributeError:
                return {"is_alive": False}
        else:
            # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                return {"is_alive": self.device.remote_conn.transport.is_active()}
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                return {"is_alive": False}
        return {"is_alive": False}

    @staticmethod
    def _create_tmp_file(config):
        """Write temp file and for use with inline config and SCP."""
        pass

    def _load_candidate_wrapper(
        self, source_file=None, source_config=None, dest_file=None, file_system=None
    ):
        """
        Transfer file to remote device for either merge or replace operations

        Returns (return_status, msg)
        """
        pass

    def load_replace_candidate(self, filename=None, config=None):
        """
        SCP file to device filesystem, defaults to candidate_config.

        Return None or raise exception
        """
        pass

    def load_merge_candidate(self, filename=None, config=None):
        """
        SCP file to remote device.

        Merge configuration in: copy <file> running-config
        """
        pass

    def _normalize_compare_config(self, diff):
        """Filter out strings that should not show up in the diff."""
        ignore_strings = [
            "Contextual Config Diffs",
            "No changes were found",
            "ntp clock-period",
        ]
        if self.auto_file_prompt:
            ignore_strings.append("file prompt quiet")

        new_list = []
        for line in diff.splitlines():
            for ignore in ignore_strings:
                if ignore in line:
                    break
            else:  # nobreak
                new_list.append(line)
        return "\n".join(new_list)

    @staticmethod
    def _normalize_merge_diff_incr(diff):
        """Make the compare config output look better.

        Cisco IOS incremental-diff output

        No changes:
        !List of Commands:
        end
        !No changes were found
        """
        new_diff = []

        changes_found = False
        for line in diff.splitlines():
            if re.search(r"order-dependent line.*re-ordered", line):
                changes_found = True
            elif "No changes were found" in line:
                # IOS in the re-order case still claims "No changes were found"
                if not changes_found:
                    return ""
                else:
                    continue

            if line.strip() == "end":
                continue
            elif "List of Commands" in line:
                continue
            # Filter blank lines and prepend +sign
            elif line.strip():
                if re.search(r"^no\s+", line.strip()):
                    new_diff.append("-" + line)
                else:
                    new_diff.append("+" + line)
        return "\n".join(new_diff)

    @staticmethod
    def _normalize_merge_diff(diff):
        """Make compare_config() for merge look similar to replace config diff."""
        new_diff = []
        for line in diff.splitlines():
            # Filter blank lines and prepend +sign
            if line.strip():
                new_diff.append("+" + line)
        if new_diff:
            new_diff.insert(0, "! incremental-diff failed; falling back to echo of merge file")
        else:
            new_diff.append("! No changes specified in merge file.")
        return "\n".join(new_diff)

    def compare_config(self):
        """
        show archive config differences <base_file> <new_file>.

        Default operation is to compare system:running-config to self.candidate_cfg
        """
        # Set defaults
        base_file = "running-config"
        base_file_system = "system:"
        if self.config_replace:
            new_file = self.candidate_cfg
        else:
            new_file = self.merge_cfg
        new_file_system = self.dest_file_system

        base_file_full = self._gen_full_path(filename=base_file, file_system=base_file_system)
        new_file_full = self._gen_full_path(filename=new_file, file_system=new_file_system)

        if self.config_replace:
            cmd = f"show archive config differences {base_file_full} {new_file_full}"
            diff = self.device.send_command(cmd)
            diff = self._normalize_compare_config(diff)
        else:
            # merge
            cmd = f"show archive config incremental-diffs {new_file_full} ignorecase"
            diff = self.device.send_command(cmd)
            if "error code 5" in diff or "returned error 5" in diff:
                diff = (
                    "You have encountered the obscure 'error 5' message. This generally "
                    "means you need to add an 'end' statement to the end of your merge changes."
                )
            elif "% Invalid" not in diff:
                diff = self._normalize_merge_diff_incr(diff)
            else:
                cmd = f"more {new_file_full}"
                diff = self.device.send_command(cmd)
                diff = self._normalize_merge_diff(diff)

        return diff.strip()

    def _file_prompt_quiet(f):
        """Decorator to toggle 'file prompt quiet' for methods that perform file operations."""
        pass

    @_file_prompt_quiet
    def _commit_handler(self, cmd):
        """
        Special handler for hostname change on commit operation. Also handles username removal
        which prompts for confirmation (username removal prompts for each user...)
        """
        current_prompt = self.device.find_prompt().strip()
        terminating_char = current_prompt[-1]
        # Look for trailing pattern that includes '#' and '>'
        pattern1 = r"[>#{}]\s*$".format(terminating_char)
        # Handle special username removal pattern
        pattern2 = r".*all username.*confirm"
        patterns = rf"(?:{pattern1}|{pattern2})"
        output = self.device.send_command(cmd, expect_string=patterns, read_timeout=90)
        loop_count = 50
        new_output = output
        for _ in range(loop_count):
            if re.search(pattern2, new_output):
                # Send confirmation if username removal
                new_output = self.device.send_command_timing(
                    "\n", strip_prompt=False, strip_command=False
                )
                output += new_output
            else:
                break
        # Reset base prompt in case hostname changed
        self.device.set_base_prompt()
        return output

    def commit_config(self, message="", revert_in=None):
        """
        If replacement operation, perform 'configure replace' for the entire config.

        If merge operation, perform copy <file> running-config.
        """
        CISCO_TIMER_MIN = 1
        CISCO_TIMER_MAX = 120
        ARCHIVE_DISABLED_MESSAGE = (
            "For Cisco devices, revert_in requires 'archive' feature to be enabled."
        )
        revert_in_min = None

        if message:
            raise NotImplementedError("Commit message not implemented for this platform")

        if revert_in is not None:
            if not self._check_archive_feature():
                raise CommitConfirmException(ARCHIVE_DISABLED_MESSAGE)
            elif not CISCO_TIMER_MIN * 60 <= revert_in <= CISCO_TIMER_MAX * 60:
                msg = (
                    "For Cisco IOS devices revert_in is rounded down to the nearest minute,"
                    "pass revert_in as a multiple of 60 between {} and {}".format(
                        CISCO_TIMER_MIN * 60, CISCO_TIMER_MAX * 60
                    )
                )
                raise CommitConfirmException(msg)
            else:
                revert_in_min = int(revert_in / 60)

        if self.has_pending_commit():
            raise CommandErrorException(
                "Configuration session already in progress, cannot perform configuration actions"
            )

        # Always generate a rollback config on commit
        self._gen_rollback_cfg()

        if self.config_replace:
            # Replace operation
            filename = self.candidate_cfg
            cfg_file = self._gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise ReplaceConfigException("Candidate config file does not exist")
            if revert_in_min and self.auto_rollback_on_error:
                cmd = "configure replace {} force revert trigger error timer {}".format(
                    cfg_file, revert_in_min
                )
            elif self.auto_rollback_on_error:
                cmd = "configure replace {} force revert trigger error".format(cfg_file)
            elif revert_in_min:
                cmd = "configure replace {} force revert timer {}".format(cfg_file, revert_in_min)
            else:
                cmd = "configure replace {} force".format(cfg_file)
            output = self._commit_handler(cmd)
            if (
                ("original configuration has been successfully restored" in output)
                or ("error" in output.lower())
                or ("not a valid config file" in output.lower())
                or ("failed" in output.lower())
            ):
                msg = "Candidate config could not be applied\n{}".format(output)
                raise ReplaceConfigException(msg)
            elif "%Please turn config archive on" in output:
                if revert_in_min:
                    raise CommitConfirmException(ARCHIVE_DISABLED_MESSAGE)
                else:
                    msg = "napalm-ios replace() requires Cisco 'archive' feature to be enabled"
                    raise ReplaceConfigException(msg)
        else:
            # Merge operation
            filename = self.merge_cfg
            cfg_file = self._gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise MergeConfigException("Merge source config file does not exist")
            if revert_in_min is not None:
                # Enter config mode with a revert timer and exit config mode
                try:
                    self.device.config_mode(
                        config_command="configure terminal revert timer {}".format(revert_in_min)
                    )
                    self.device.exit_config_mode()
                except ValueError:
                    raise MergeConfigException(ARCHIVE_DISABLED_MESSAGE)

            cmd = "copy {} running-config".format(cfg_file)
            output = self._commit_handler(cmd)
            if "Invalid input detected" in output:
                self.rollback()
                err_header = "Configuration merge failed; automatic rollback attempted"
                merge_error = "{0}:\n{1}".format(err_header, output)
                raise MergeConfigException(merge_error)

        # After a commit - we no longer know whether this is configured or not.
        self.prompt_quiet_configured = None

        if revert_in_min is None:
            # Save config to startup (both replace and merge)
            output += self.device.save_config()

    def _check_archive_feature(self):
        cmd = "show archive"
        output = self.device.send_command(cmd)
        if "Archive feature not enabled" in output:
            return False
        return True

    def has_pending_commit(self):
        pending_commits = self._get_pending_commits()
        return bool(pending_commits)

    def _get_pending_commits(self):
        if self._check_archive_feature():
            cmd = "show archive config rollback timer"
            output = self.device.send_command(cmd)
        else:
            return {}
        if "No Rollback Confirmed Change pending" in output:
            return {}
        match_strings = r"|".join(
            [
                r"Time configured.*?: (?P<configured>.*)",
                r"Timer type: (?P<type>.*)",
                r"Timer value: (?P<timer>.*)",
                r"User: (?P<user>.*)",
            ]
        )
        keys = ["configured", "type", "timer", "user"]
        matches = re.finditer(match_strings, output)
        pending_commits = {}
        for match in matches:
            for key in keys:
                if match.groupdict().get(key):
                    pending_commits.update({key: match.groupdict().get(key)})

        return pending_commits

    def confirm_commit(self):
        """Send final commit to confirm an in-proces commit that requires confirmation."""
        pass

    def discard_config(self):
        """Discard loaded candidate configurations."""
        self._discard_config()

    @_file_prompt_quiet
    def _discard_config(self):
        """Set candidate_cfg to current running-config. Erase the merge_cfg file."""
        discard_candidate = f"copy running-config {self._gen_full_path(self.candidate_cfg)}"
        discard_merge = f"copy null: {self._gen_full_path(self.merge_cfg)}"
        self.device.send_command(discard_candidate)
        self.device.send_command(discard_merge)

    def rollback(self):
        """Rollback configuration to filename or to self.rollback_cfg file."""
        if self.has_pending_commit():
            if self._get_pending_commits().get("user") == self.username:
                cmd = "configure revert now"
                self._commit_handler(cmd)
                self.device.save_config()
            else:
                raise CommitConfirmException(
                    "Configuration session active but not owned by {} cannot rollback".format(
                        self.username
                    )
                )
        else:
            filename = self.rollback_cfg
            cfg_file = self._gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise ReplaceConfigException("Rollback config file does not exist")
            cmd = "configure replace {} force".format(cfg_file)
            self._commit_handler(cmd)

            # After a rollback - we no longer know whether this is configured or not.
            self.prompt_quiet_configured = None

            # Save config to startup
            self.device.save_config()

    def _inline_tcl_xfer(
        self, source_file=None, source_config=None, dest_file=None, file_system=None
    ):
        """
        Use Netmiko InlineFileTransfer (TCL) to transfer file or config to remote device.

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        pass

    def _scp_file(self, source_file, dest_file, file_system):
        """
        SCP file to remote device.

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        pass

    def _xfer_file(
        self,
        source_file=None,
        source_config=None,
        dest_file=None,
        file_system=None,
        TransferClass=FileTransfer,
    ):
        """Transfer file to remote device.

        By default, this will use Secure Copy if self.inline_transfer is set, then will use
        Netmiko InlineTransfer method to transfer inline using either SSH or telnet (plus TCL
        onbox).

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        pass

    def _gen_full_path(self, filename, file_system=None):
        """Generate full file path on remote device."""
        if file_system is None:
            return "{}/{}".format(self.dest_file_system, filename)
        else:
            if ":" not in file_system:
                raise ValueError("Invalid file_system specified: {}".format(file_system))
            return "{}/{}".format(file_system, filename)

    @_file_prompt_quiet
    def _gen_rollback_cfg(self):
        """Save a configuration that can be used for rollback."""
        cfg_file = self._gen_full_path(self.rollback_cfg)
        cmd = f"copy running-config {cfg_file}"
        self.device.send_command(cmd)

    def _check_file_exists(self, cfg_file):
        """
        Check that the file exists on remote device using full path.

        cfg_file is full path i.e. flash:/file_name

        For example
        # dir flash:/candidate_config.txt
        Directory of flash:/candidate_config.txt

        33  -rw-        5592  Dec 18 2015 10:50:22 -08:00  candidate_config.txt

        return boolean
        """
        cmd = f"dir {cfg_file}"
        success_pattern = f"Directory of {cfg_file}"
        output = self.device.send_command(cmd)
        if "Error opening" in output:
            return False
        elif success_pattern in output:
            return True
        return False

    @staticmethod
    def _send_command_postprocess(output):
        """
        Cleanup actions on send_command() for NAPALM getters.

        Remove "Load for five sec; one minute if in output"
        Remove "Time source is"
        """
        output = re.sub(r"^Load for five secs.*$", "", output, flags=re.M)
        output = re.sub(r"^Time source is .*$", "", output, flags=re.M)
        return output.strip()

    def _is_vss(self):
        """
        Returns True if a Virtual Switching System (VSS) is setup
        """
        pass

    def get_optics(self):
        pass

    def get_lldp_neighbors(self):
        """IOS implementation of get_lldp_neighbors."""
        pass

    def get_lldp_neighbors_detail(self, interface=""):
        pass

    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Cisco IOS Device.

        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes) = (0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(",")
        for element in time_list:
            if re.search("year", element):
                years = int(element.split()[0])
            elif re.search("week", element):
                weeks = int(element.split()[0])
            elif re.search("day", element):
                days = int(element.split()[0])
            elif re.search("hour", element):
                hours = int(element.split()[0])
            elif re.search("minute", element):
                minutes = int(element.split()[0])

        uptime_sec = (
            (years * YEAR_SECONDS)
            + (weeks * WEEK_SECONDS)
            + (days * DAY_SECONDS)
            + (hours * 3600)
            + (minutes * 60)
        )
        return uptime_sec

    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = "Cisco"
        uptime = -1
        serial_number, fqdn, os_version, hostname, domain_name = ("Unknown",) * 5

        # obtain output from device
        show_ver = self._send_command("show version")
        show_hosts = self._send_command("show hosts")
        show_ip_int_br = self._send_command("show ip interface brief")

        # uptime/serial_number/IOS version
        for line in show_ver.splitlines():
            if " uptime is " in line:
                hostname, uptime_str = line.split(" uptime is ")
                uptime = self.parse_uptime(uptime_str)
                hostname = hostname.strip()

            if "Processor board ID" in line:
                _, serial_number = line.split("Processor board ID ")
                serial_number = serial_number.strip()

            if re.search(r"Cisco IOS Software", line):
                try:
                    _, os_version = line.split("Cisco IOS Software, ")
                except ValueError:
                    # Handle 'Cisco IOS Software [Denali],'
                    _, os_version = re.split(r"Cisco IOS Software \[.*?\], ", line)
            elif re.search(r"IOS \(tm\).+Software", line):
                _, os_version = line.split("IOS (tm) ")

            os_version = os_version.strip()

        # Determine domain_name and fqdn
        for line in show_hosts.splitlines():
            if "Default domain" in line:
                _, domain_name = line.split("Default domain is ")
                domain_name = domain_name.strip()
                break
        if domain_name != "Unknown" and hostname != "Unknown":
            fqdn = "{}.{}".format(hostname, domain_name)

        # model filter
        try:
            match_model = re.search(r"Cisco (.+?) .+bytes of", show_ver, flags=re.IGNORECASE)
            model = match_model.group(1)
        except AttributeError:
            model = "Unknown"

        # interface_list filter
        interface_list = []
        # Cisco adds a message "Any interface listed with OK..." in certain situations
        show_ip_int_br = re.split(r"Any interface listed with.*", show_ip_int_br)[-1]
        show_ip_int_br = show_ip_int_br.strip()
        for line in show_ip_int_br.splitlines():
            if "Interface " in line:
                continue
            interface = line.split()[0]
            interface_list.append(interface)

        return {
            "uptime": float(uptime),
            "vendor": vendor,
            "os_version": str(os_version),
            "serial_number": str(serial_number),
            "model": str(model),
            "hostname": str(hostname),
            "fqdn": fqdn,
            "interface_list": interface_list,
        }

    def get_interfaces(self):
        """
        Get interface details.

        last_flapped is not implemented

        Example Output:

        {   u'Vlan1': {   'description': u'N/A',
                      'is_enabled': True,
                      'is_up': True,
                      'last_flapped': -1.0,
                      'mac_address': u'a493.4cc1.67a7',
                      'speed': 100},
        u'Vlan100': {   'description': u'Data Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100},
        u'Vlan200': {   'description': u'Voice Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100}}
        """
        # default values.
        last_flapped = -1.0

        command = "show interfaces"
        output = self._send_command(command)

        interface = description = mac_address = speed = speedformat = ""
        is_enabled = is_up = None

        interface_dict = {}
        for line in output.splitlines():
            interface_regex_1 = r"^(\S+?)\s+is\s+(.+?),\s+line\s+protocol\s+is\s+(\S+)"
            interface_regex_2 = r"^(\S+)\s+is\s+(up|down)"
            interface_regex_3 = (
                r"^(Control Plane Interface)"
                r"\s+is\s+(.+?),\s+line\s+protocol\s+is\s+(\S+)"
            )
            for pattern in (interface_regex_1, interface_regex_2, interface_regex_3):
                interface_match = re.search(pattern, line)
                if interface_match:
                    interface = interface_match.group(1)
                    status = interface_match.group(2)
                    try:
                        protocol = interface_match.group(3)
                    except IndexError:
                        protocol = ""
                    if "admin" in status.lower():
                        is_enabled = False
                    else:
                        is_enabled = True
                    if protocol:
                        is_up = bool("up" in protocol)
                    else:
                        is_up = bool("up" in status)
                    break

            mac_addr_regex = r"^\s+Hardware.+address\s+is\s+({})".format(MAC_REGEX)
            if re.search(mac_addr_regex, line):
                mac_addr_match = re.search(mac_addr_regex, line)
                mac_address = napalm.base.helpers.mac(mac_addr_match.groups()[0])

            descr_regex = r"^\s+Description:\s+(.+?)$"
            if re.search(descr_regex, line):
                descr_match = re.search(descr_regex, line)
                description = descr_match.groups()[0]

            speed_regex = r"^\s+MTU\s+(\d+).+BW\s+(\d+)\s+([KMG]?b)"
            if re.search(speed_regex, line):
                speed_match = re.search(speed_regex, line)
                mtu = int(speed_match.groups()[0])
                speed = speed_match.groups()[1]
                speedformat = speed_match.groups()[2]
                speed = float(speed)
                if speedformat.startswith("Kb"):
                    speed = speed / 1000.0
                elif speedformat.startswith("Gb"):
                    speed = speed * 1000

                if interface == "":
                    raise ValueError(
                        "Interface attributes were \
                                      found without any known interface"
                    )
                if not isinstance(is_up, bool) or not isinstance(is_enabled, bool):
                    raise ValueError("Did not correctly find the interface status")

                interface_dict[interface] = {
                    "is_enabled": is_enabled,
                    "is_up": is_up,
                    "description": description,
                    "mac_address": mac_address,
                    "last_flapped": last_flapped,
                    "mtu": mtu,
                    "speed": speed,
                }

                interface = description = mac_address = speed = speedformat = ""
                is_enabled = is_up = None

        return interface_dict

    def get_interfaces_ip(self):
        """
        Get interface ip details.

        Returns a dict of dicts

        Example Output:

        {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
            u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                'ipv6': {   u'1::1': {   'prefix_length': 64},
                                            u'2001:DB8:1::1': {   'prefix_length': 64},
                                            u'2::': {   'prefix_length': 64},
                                            u'FE80::3': {   'prefix_length': 10}}},
            u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
            u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
            u'Vlan100': {   'ipv4': {   u'10.40.0.1': {   'prefix_length': 24},
                                        u'10.41.0.1': {   'prefix_length': 24},
                                        u'10.65.0.1': {   'prefix_length': 24}}},
            u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}
        """
        pass

    @staticmethod
    def bgp_time_conversion(bgp_uptime):
        """
        Convert string time to seconds.

        Examples
        00:14:23
        00:13:40
        00:00:21
        00:00:13
        00:00:49
        1d11h
        1d17h
        1w0d
        8w5d
        1y28w
        never
        """
        pass

    def get_bgp_config(self, group="", neighbor=""):
        """
        Parse BGP config params into a dict
            :param group='':
            :param neighbor='':
        """
        pass

    def get_bgp_neighbors(self):
        """BGP neighbor information.

        Supports both IPv4 and IPv6. vrf aware
        """
        pass

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        pass

    def get_interfaces_counters(self):
        """
        Return interface counters and errors.

        'tx_errors': int,
        'rx_errors': int,
        'tx_discards': int,
        'rx_discards': int,
        'tx_octets': int,
        'rx_octets': int,
        'tx_unicast_packets': int,
        'rx_unicast_packets': int,
        'tx_multicast_packets': int,
        'rx_multicast_packets': int,
        'tx_broadcast_packets': int,
        'rx_broadcast_packets': int,

        Currently doesn't determine output broadcasts, multicasts
        """
        pass

    def get_environment(self):
        """
        Get environment facts.

        power and fan are currently not implemented
        cpu is using 1-minute average
        cpu hard-coded to cpu0 (i.e. only a single CPU)
        """
        pass

    def get_arp_table(self, vrf=""):
        """
        Get arp table information.

        Return a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)

        For example::
            [
                {
                    "interface": "MgmtEth0/RSP0/CPU0/0",
                    "mac": "5c:5e:ab:da:3c:f0",
                    "ip": "172.17.17.1",
                    "age": 1454496274.84,
                },
                {
                    "interface": "MgmtEth0/RSP0/CPU0/0",
                    "mac": "66:0e:94:96:e0:ff",
                    "ip": "172.17.17.2",
                    "age": 1435641582.49,
                },
            ]
        """
        pass

    def cli(self, commands, encoding="text"):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.

        Example input:
        ['show clock', 'show calendar']

        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}

        """
        if encoding not in ("text",):
            raise NotImplementedError("%s is not a supported encoding" % encoding)
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self._send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_ntp_peers(self):
        """Implementation of get_ntp_peers for IOS."""
        pass

    def get_ntp_servers(self):
        """Implementation of get_ntp_servers for IOS.

        Returns the NTP servers configuration as dictionary.
        The keys of the dictionary represent the IP Addresses of the servers.
        Inner dictionaries do not have yet any available keys.
        Example::
            {
                "192.168.0.1": {},
                "17.72.148.53": {},
                "37.187.56.220": {},
                "162.158.20.18": {},
            }
        """
        pass

    def get_ntp_stats(self):
        """Implementation of get_ntp_stats for IOS."""
        pass

    def get_mac_address_table(self):
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)

        Format1:
        Destination Address  Address Type  VLAN  Destination Port
        -------------------  ------------  ----  --------------------
        6400.f1cf.2cc6          Dynamic       1     Wlan-GigabitEthernet0

        Cat 6500:
        Legend: * - primary entry
                age - seconds since last seen
                n/a - not available

          vlan   mac address     type    learn     age              ports
        ------+----------------+--------+-----+----------+--------------------------
        *  999  1111.2222.3333   dynamic  Yes          0   Port-channel1
           999  1111.2222.3333   dynamic  Yes          0   Port-channel1

        Cat 4948
        Unicast Entries
         vlan   mac address     type        protocols               port
        -------+---------------+--------+---------------------+--------------------
         999    1111.2222.3333   dynamic ip                    Port-channel1

        Cat 2960
        Mac Address Table
        -------------------------------------------

        Vlan    Mac Address       Type        Ports
        ----    -----------       --------    -----
        All    1111.2222.3333    STATIC      CPU
        """
        pass

    def get_probes_config(self):
        pass

    def _get_vrfs(self, ip_version=None):
        """
        Returns list of all VRFs (if ip_version=None) or VRFs which have ipv4 (ip_version=4) or
        ipv6 (ip_version=6) configured
        param ip_version can contain None, 4 or 6
        """
        pass

    def _get_bgp_route_attr(self, destination, vrf, next_hop, ip_version=4):
        """
        Returns bgp attributes of specific prefix. Result is used as a value
        of 'protocol_attributes' key used in get_route_to function
        """
        pass

    def get_route_to(self, destination="", protocol="", longer=False):
        """
        Only IPv4 is supported
        VRFs are supported

        Output example:

        {
            "1.0.4.0/24": [
                {
                    "protocol": "bgp",
                    "outgoing_interface": "",
                    "age": 1123200,
                    "current_active": true,
                    "routing_table": "TEST",
                    "last_active": true,
                    "protocol_attributes": {
                        "as_path": "65201 8244 3269 65020 65017",
                        "remote_address": "10.105.113.164",
                        "communities": [
                            "RT:65417:2"
                        ],
                        "local_preference": 100,
                        "remote_as": 65417,
                        "local_as": 65417
                    },
                    "next_hop": "10.105.113.164",
                    "selected_next_hop": true,
                    "inactive_reason": "",
                    "preference": 0
                }
            ]
        }
        """
        pass

    def get_snmp_information(self):
        """
        Returns a dict of dicts

        Example Output:

        {   'chassis_id': u'Asset Tag 54670',
        'community': {   u'private': {   'acl': u'12', 'mode': u'rw'},
                         u'public': {   'acl': u'11', 'mode': u'ro'},
                         u'public_named_acl': {   'acl': u'ALLOW-SNMP-ACL',
                                                  'mode': u'ro'},
                         u'public_no_acl': {   'acl': u'N/A', 'mode': u'ro'}},
        'contact': u'Joe Smith',
        'location': u'123 Anytown USA Rack 404'}

        """
        pass

    def get_users(self):
        """
        Returns a dictionary with the configured users.
        The keys of the main dictionary represents the username.
        The values represent the details of the user,
        represented by the following keys:

            * level (int)
            * password (str)
            * sshkeys (list)

        *Note: sshkeys on ios is the ssh key fingerprint

        The level is an integer between 0 and 15, where 0 is the
        lowest access and 15 represents full access to the device.
        """
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
        destination,
        source=C.TRACEROUTE_SOURCE,
        ttl=C.TRACEROUTE_TTL,
        timeout=C.TRACEROUTE_TIMEOUT,
        vrf=C.TRACEROUTE_VRF,
    ):
        """
        Executes traceroute on the device and returns a dictionary with the result.

        :param destination: Host or IP Address of the destination
        :param source: Use a specific IP Address to execute the traceroute
        :type source: optional
        :param ttl: Maximum number of hops -> int (0-255)
        :type ttl: optional
        :param timeout: Number of seconds to wait for response -> int (1-3600)
        :type timeout: optional
        :param vrf: Use a specific VRF to execute the traceroute
        :type vrf: optional

        Output dictionary has one of the following keys:

            * success
            * error

        In case of success, the keys of the dictionary represent the hop ID, while values are
        dictionaries containing the probes results:
            * rtt (float)
            * ip_address (str)
            * host_name (str)
        """
        pass

    def get_network_instances(self, name=""):
        pass

    def get_config(self, retrieve="all", full=False, sanitized=False, format="text"):
        """Implementation of get_config for IOS.

        Returns the startup or/and running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since IOS does not support candidate configuration.
        """

        # The output of get_config should be directly usable by load_replace_candidate()
        # IOS adds some extra, unneeded lines that should be filtered.
        filter_strings = [
            r"^Building configuration.*$",
            r"^Current configuration :.*$",
            r"^! Last configuration change at.*$",
            r"^! NVRAM config last updated at.*$",
        ]
        filter_pattern = generate_regex_or(filter_strings)

        configs = {"startup": "", "running": "", "candidate": ""}
        # IOS only supports "all" on "show run"
        run_full = " all" if full else ""

        if retrieve in ("startup", "all"):
            command = "show startup-config"
            output = self._send_command(command)
            output = re.sub(filter_pattern, "", output, flags=re.M)
            configs["startup"] = output.strip()

        if retrieve in ("running", "all"):
            command = f"show running-config{run_full}"
            output = self._send_command(command)
            output = re.sub(filter_pattern, "", output, flags=re.M)
            configs["running"] = output.strip()

        if sanitized:
            return sanitize_configs(configs, C.CISCO_SANITIZE_FILTERS)

        return configs

    def get_ipv6_neighbors_table(self):
        """
        Get IPv6 neighbors table information.
        Return a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float) in seconds
            * state (string)
        For example::
            [
                {
                    "interface": "MgmtEth0/RSP0/CPU0/0",
                    "mac": "5c:5e:ab:da:3c:f0",
                    "ip": "2001:db8:1:1::1",
                    "age": 1454496274.84,
                    "state": "REACH",
                },
                {
                    "interface": "MgmtEth0/RSP0/CPU0/0",
                    "mac": "66:0e:94:96:e0:ff",
                    "ip": "2001:db8:1:1::2",
                    "age": 1435641582.49,
                    "state": "STALE",
                },
            ]
        """
        pass

    @property
    def dest_file_system(self):
        # The self.device check ensures napalm has an open connection
        pass

    def get_vlans(self):
        pass

    def _get_vlan_all_ports(self, output):
        pass

    def _get_vlan_from_id(self):
        pass
