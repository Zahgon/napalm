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
from builtins import super
import ipaddress
import re
import socket
from collections import defaultdict

# import external lib
from netutils.interface import canonical_interface_name

# import NAPALM Base
from napalm.base import helpers
from napalm.base.exceptions import CommandErrorException, ReplaceConfigException
from napalm.nxos import NXOSDriverBase

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
    r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:"
    r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}"
)
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = r"(?:{}|{}|{})".format(IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3)
IPV4_OR_IPV6_REGEX = r"(?:{}|{})".format(IPV4_ADDR_REGEX, IPV6_ADDR_REGEX)

MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"
VLAN_REGEX = r"\d{1,4}"

RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))

# Period needed for 32-bit AS Numbers
ASN_REGEX = r"[\d\.]+"

RE_IP_ROUTE_VIA_REGEX = re.compile(
    r"    (?P<used>[\*| ])via ((?P<ip>" + IPV4_ADDR_REGEX + r")"
    r"(%(?P<vrf>\S+))?, )?"
    r"((?P<int>[\w./:]+), )?\[(\d+)/(?P<metric>\d+)\]"
    r", (?P<age>[\d\w:]+), (?P<source>[\w]+)(-(?P<procnr>\d+))?"
    r"(?P<rest>.*)"
)
RE_RT_VRF_NAME = re.compile(r"VRF \"(\S+)\"")
RE_RT_IPV4_ROUTE_PREF = re.compile(r"(" + IPV4_ADDR_REGEX + r"/\d{1,2}), ubest.*")

RE_BGP_PROTO_TAG = re.compile(r"BGP Protocol Tag\s+: (\d+)")
RE_BGP_REMOTE_AS = re.compile(r"remote AS (" + ASN_REGEX + r")")
RE_BGP_COMMUN = re.compile(r"[ ]{10}([\S ]+)")


def parse_intf_section(interface):
    """Parse a single entry from show interfaces output.

    Different cases:
    mgmt0 is up
    admin state is up

    Ethernet2/1 is up
    admin state is up, Dedicated Interface

    Vlan1 is down (Administratively down), line protocol is down, autostate enabled

    Ethernet154/1/48 is up (with no 'admin state')
    """
    interface = interface.strip()
    re_protocol = (
        r"^(?P<intf_name>\S+?)\s+is\s+(?P<status>.+?)"
        r",\s+line\s+protocol\s+is\s+(?P<protocol>\S+).*$"
    )
    re_intf_name_state = r"^(?P<intf_name>\S+) is (?P<intf_state>\S+).*"
    re_is_enabled_1 = r"^admin state is (?P<is_enabled>\S+)$"
    re_is_enabled_2 = r"^admin state is (?P<is_enabled>\S+), "
    re_is_enabled_3 = r"^.* is down.*Administratively down.*$"
    re_mac = r"^\s+Hardware:\s+(?P<hardware>.*),\s+address:\s+(?P<mac_address>\S+) "
    re_speed = r"\s+(MTU (?P<mtu>\S+)\s+bytes)?,\s+BW\s+(?P<speed>\S+)\s+(?P<speed_unit>\S+).*$"
    re_mtu_nve = r"\s+MTU (?P<mtu_nve>\S+)\s+bytes.*$"
    re_description_1 = r"^\s+Description:\s+(?P<description>.*)  (?:MTU|Internet)"
    re_description_2 = r"^\s+Description:\s+(?P<description>.*)$"
    re_hardware = r"^.* Hardware: (?P<hardware>\S+)$"

    # Check for 'protocol is ' lines
    match = re.search(re_protocol, interface, flags=re.M)
    if match:
        intf_name = match.group("intf_name")
        status = match.group("status")
        protocol = match.group("protocol")

        if "admin" in status.lower():
            is_enabled = False
        else:
            is_enabled = True
        is_up = bool("up" in protocol)

    else:
        # More standard is up, next line admin state is lines
        match = re.search(re_intf_name_state, interface)
        intf_name = canonical_interface_name(match.group("intf_name"))
        intf_state = match.group("intf_state").strip()
        is_up = True if intf_state == "up" else False

        admin_state_present = re.search("admin state is", interface)
        if admin_state_present:
            # Parse cases where 'admin state' string exists
            for x_pattern in [re_is_enabled_1, re_is_enabled_2]:
                match = re.search(x_pattern, interface, flags=re.M)
                if match:
                    is_enabled = match.group("is_enabled").strip()
                    is_enabled = True if re.search("up", is_enabled) else False
                    break
            else:
                msg = "Error parsing intf, 'admin state' never detected:\n\n{}".format(interface)
                raise ValueError(msg)
        else:
            # No 'admin state' should be 'is up' or 'is down' strings
            # If interface is up; it is enabled
            is_enabled = True
            if not is_up:
                match = re.search(re_is_enabled_3, interface, flags=re.M)
                if match:
                    is_enabled = False

    match = re.search(re_mac, interface, flags=re.M)
    if match:
        mac_address = match.group("mac_address")
        mac_address = helpers.mac(mac_address)
    else:
        mac_address = ""

    match = re.search(re_hardware, interface, flags=re.M)
    speed_exist = True
    if match:
        if match.group("hardware") == "NVE":
            match = re.search(re_mtu_nve, interface, flags=re.M)
            mtu = int(match.group("mtu_nve"))
            speed_exist = False

    if speed_exist:
        match = re.search(re_speed, interface, flags=re.M)
        speed_data = match.groupdict(-1)
        speed = float(speed_data["speed"])
        mtu = int(speed_data["mtu"])
        speed_unit = speed_data["speed_unit"]
        speed_unit = speed_unit.rstrip(",")
        if speed_unit not in ["Kbit", "Kbit/sec"]:
            msg = "Unexpected speed unit in show interfaces parsing:\n\n{}".format(interface)
            raise ValueError(msg)
        speed = float(speed / 1000.0)
    else:
        speed = -1.0

    description = ""
    for x_pattern in [re_description_1, re_description_2]:
        match = re.search(x_pattern, interface, flags=re.M)
        if match:
            description = match.group("description")
            break

    return {
        intf_name: {
            "description": description,
            "is_enabled": is_enabled,
            "is_up": is_up,
            "last_flapped": -1.0,
            "mac_address": mac_address,
            "mtu": mtu,
            "speed": speed,
        }
    }


def convert_hhmmss(hhmmss):
    """Convert hh:mm:ss to seconds."""
    pass


def bgp_time_conversion(bgp_uptime):
    """Convert string time to seconds.

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


def bgp_normalize_table_data(bgp_table):
    """The 'show bgp all summary vrf all' table can have entries that wrap multiple lines.

    2001:db8:4:701::2
                4 65535  163664  163693      145    0    0     3w2d 3
    2001:db8:e0:dd::1
                4    10  327491  327278      145    0    0     3w1d 4
    2001:db8:e0:df::
                4    12345678
                         327465  327268      145    0    0     3w1d 4

    Normalize this so the line wrap doesn't exit.
    """
    pass


def bgp_table_parser(bgp_table):
    """Generator that parses a line of bgp summary table and returns a dict compatible with NAPALM

    Example line:
    10.2.1.14       4    10  472516  472238      361    0    0     3w1d 9
    """
    pass


def bgp_summary_parser(bgp_summary):
    """Parse 'show bgp all summary vrf' output information from NX-OS devices."""
    pass


class NXOSSSHDriver(NXOSDriverBase):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout=timeout, optional_args=optional_args)
        self.platform = "nxos_ssh"
        self.connector_type_map = {
            "1000base-LH": "LC_CONNECTOR",
            "1000base-SX": "LC_CONNECTOR",
            "1000base-T": "Unknown",
            "10Gbase-LR": "LC_CONNECTOR",
            "10Gbase-SR": "LC_CONNECTOR",
            "SFP-H10GB-CU1M": "DAC_CONNECTOR",
            "SFP-H10GB-CU1.45M": "DAC_CONNECTOR",
            "SFP-H10GB-CU3M": "DAC_CONNECTOR",
            "SFP-H10GB-CU3.45M": "DAC_CONNECTOR",
        }

    def open(self):
        pass

    def close(self):
        self._netmiko_close()

    def _send_command(self, command, raw_text=False, cmd_verify=True):
        """
        Wrapper for Netmiko's send_command method.

        raw_text argument is not used and is for code sharing with NX-API.
        """
        return self.device.send_command(command, cmd_verify=cmd_verify)

    def _send_command_list(self, commands, expect_string=None, **kwargs):
        """Send a list of commands using Netmiko"""
        return self.device.send_multiline(commands, expect_string=expect_string, **kwargs)

    def _send_config(self, commands):
        if isinstance(commands, str):
            commands = [command for command in commands.splitlines() if command]
        return self.device.send_config_set(commands)

    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Cisco IOS Device.
        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes, seconds) = (0, 0, 0, 0, 0, 0)

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
            elif re.search("second", element):
                seconds = int(element.split()[0])

        uptime_sec = (
            (years * YEAR_SECONDS)
            + (weeks * WEEK_SECONDS)
            + (days * DAY_SECONDS)
            + (hours * 3600)
            + (minutes * 60)
            + seconds
        )
        return uptime_sec

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        null = chr(0)
        try:
            if self.device is None:
                return {"is_alive": False}
            else:
                # Try sending ASCII null byte to maintain the connection alive
                self._send_command(null, cmd_verify=False)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable,
            # hence return False.
            return {"is_alive": False}
        return {"is_alive": self.device.remote_conn.transport.is_active()}

    def _copy_run_start(self):
        output = self.device.save_config()
        if "complete" in output.lower():
            return True
        else:
            msg = "Unable to save running-config to startup-config!"
            raise CommandErrorException(msg)

    def _load_cfg_from_checkpoint(self):
        commands = [
            "terminal dont-ask",
            "rollback running-config file {}".format(self.candidate_cfg),
            "no terminal dont-ask",
        ]

        rollback_result = self._send_command_list(commands, expect_string=r"[#>]", read_timeout=90)
        msg = rollback_result
        if "Rollback failed." in msg:
            raise ReplaceConfigException(msg)

    def rollback(self):
        if not self._check_file_exists(self.rollback_cfg):
            msg = f"Rollback file '{self.rollback_cfg}' does not exist on device."
            raise ReplaceConfigException(msg)

        commands = [
            "terminal dont-ask",
            "rollback running-config file {}".format(self.rollback_cfg),
            "no terminal dont-ask",
        ]
        result = self._send_command_list(commands, expect_string=r"[#>]", read_timeout=90)
        if "completed" not in result.lower():
            raise ReplaceConfigException(result)
        # If hostname changes ensure Netmiko state is updated properly
        self._netmiko_device.set_base_prompt()
        self._copy_run_start()

    def _apply_key_map(self, key_map, table):
        pass

    def _convert_uptime_to_seconds(self, uptime_facts):
        pass

    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = "Cisco"
        uptime = -1
        serial_number, fqdn, os_version, hostname, domain_name, model = ("",) * 6

        # obtain output from device
        show_ver = self._send_command("show version")
        show_hosts = self._send_command("show hosts")
        show_int_status = self._send_command("show interface status")
        show_hostname = self._send_command("show hostname")

        try:
            show_inventory_table = self._get_command_table(
                "show inventory | json", "TABLE_inv", "ROW_inv"
            )
            if isinstance(show_inventory_table, dict):
                show_inventory_table = [show_inventory_table]

            for row in show_inventory_table:
                if row["name"] == '"Chassis"' or row["name"] == "Chassis":
                    serial_number = row.get("serialnum", "")
                    break
        except ValueError:
            show_inventory = self._send_command("show inventory")
            find_regexp = r"^NAME:\s+\"(.*)\",.*\n^PID:.*SN:\s+(\w*)"
            find = re.findall(find_regexp, show_inventory, re.MULTILINE)
            for row in find:
                if row[0] == "Chassis":
                    serial_number = row[1]
                    break

        # uptime/serial_number/IOS version
        for line in show_ver.splitlines():
            if " uptime is " in line:
                _, uptime_str = line.split(" uptime is ")
                uptime = self.parse_uptime(uptime_str)

            if "system: " in line or line.strip().startswith("NXOS: version"):
                line = line.strip()
                os_version = line.split()[2]
                os_version = os_version.strip()

            if "cisco" in line and "hassis" in line:
                match = re.search(r".cisco (.*) \(", line)
                if match:
                    model = match.group(1).strip()
                match = re.search(r".cisco (.* [cC]hassis)", line)
                if match:
                    model = match.group(1).strip()

        hostname = show_hostname.strip()

        # Determine domain_name and fqdn
        for line in show_hosts.splitlines():
            if "Default domain" in line:
                _, domain_name = re.split(r".*Default domain.*is ", line)
                domain_name = domain_name.strip()
                break
        if hostname.count(".") >= 2:
            fqdn = hostname
            # Remove domain name from hostname
            if domain_name:
                hostname = re.sub(re.escape(domain_name) + "$", "", hostname)
                hostname = hostname.strip(".")
        elif domain_name:
            fqdn = "{}.{}".format(hostname, domain_name)

        # interface_list filter
        interface_list = []
        show_int_status = show_int_status.strip()
        # Remove the header information
        show_int_status = re.sub(
            r"(?:^---------+$|^Port .*$|^ .*$)", "", show_int_status, flags=re.M
        )
        for line in show_int_status.splitlines():
            if not line:
                continue
            interface = line.split()[0]
            # Return canonical interface name
            interface_list.append(canonical_interface_name(interface))

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

        {   u'Vlan1': {   'description': u'',
                      'is_enabled': True,
                      'is_up': True,
                      'last_flapped': -1.0,
                      'mac_address': u'a493.4cc1.67a7',
                      'speed': 100.0},
        u'Vlan100': {   'description': u'Data Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100.0},
        u'Vlan200': {   'description': u'Voice Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100.0}}
        """
        interfaces = {}
        command = "show interface"
        output = self._send_command(command)
        if not output:
            return {}

        # Break output into per-interface sections (note, separator text is retained)
        separator1 = r"^\S+\s+is \S+.*\nadmin state is.*$"
        separator2 = r"^.* is .*, line protocol is .*$"
        separator3 = r"^.* is (?:down|up).*$"
        separators = r"({}|{}|{})".format(separator1, separator2, separator3)
        interface_lines = re.split(separators, output, flags=re.M)

        if len(interface_lines) == 1:
            msg = "Unexpected output data in '{}':\n\n{}".format(command, interface_lines)
            raise ValueError(msg)

        # Get rid of the blank data at the beginning
        interface_lines.pop(0)

        # Must be pairs of data (the separator and section corresponding to it)
        if len(interface_lines) % 2 != 0:
            msg = "Unexpected output data in '{}':\n\n{}".format(command, interface_lines)
            raise ValueError(msg)

        # Combine the separator and section into one string
        intf_iter = iter(interface_lines)
        try:
            new_interfaces = [line + next(intf_iter, "") for line in intf_iter]
        except TypeError:
            raise ValueError()

        for entry in new_interfaces:
            interfaces.update(parse_intf_section(entry))

        return interfaces

    def get_bgp_neighbors(self):
        """BGP neighbor information.

        Supports VRFs and IPv4 and IPv6 AFIs

        {
        "global": {
            "router_id": "1.1.1.103",
            "peers": {
                "10.99.99.2": {
                    "is_enabled": true,
                    "uptime": -1,
                    "remote_as": 22,
                    "address_family": {
                        "ipv4": {
                            "sent_prefixes": -1,
                            "accepted_prefixes": -1,
                            "received_prefixes": -1
                        }
                    },
                    "remote_id": "0.0.0.0",
                    "local_as": 22,
                    "is_up": false,
                    "description": ""
                 }
            }
        }
        """
        pass

    def cli(self, commands, encoding="text"):
        if encoding not in ("text",):
            raise NotImplementedError("%s is not a supported encoding" % encoding)
        cli_output = {}
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self._send_command(command)
            cli_output[str(command)] = output
        return cli_output

    def get_network_instances(self, name=""):
        """
        get_network_instances implementation for NX-OS
        """
        pass

    def get_environment(self):
        """
        Get environment facts.

        power and fan are currently not implemented
        cpu is using 1-minute average
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
                    "age": 12.0,
                },
                {
                    "interface": "MgmtEth0/RSP0/CPU0/0",
                    "mac": "66:0e:94:96:e0:ff",
                    "ip": "172.17.17.2",
                    "age": 14.0,
                },
            ]
        """
        pass

    def _get_ntp_entity(self, peer_type):
        pass

    def get_ntp_peers(self):
        pass

    def get_ntp_servers(self):
        pass

    def get_interfaces_ip(self):
        """
        Get interface IP details. Returns a dictionary of dictionaries.

        Sample output:
        {
            "Ethernet2/3": {
                "ipv4": {
                    "4.4.4.4": {
                        "prefix_length": 16
                    }
                },
                "ipv6": {
                    "2001:db8::1": {
                        "prefix_length": 10
                    },
                    "fe80::2ec2:60ff:fe4f:feb2": {
                        "prefix_length": "128"
                    }
                }
            },
            "Ethernet2/2": {
                "ipv4": {
                    "2.2.2.2": {
                        "prefix_length": 27
                    }
                }
            }
        }
        """
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

        Legend:
        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC
        age - seconds since last seen,+ - primary entry using vPC Peer-Link,
        (T) - True, (F) - False
           VLAN     MAC Address      Type      age     Secure NTFY Ports/SWID.SSID.LID
        ---------+-----------------+--------+---------+------+----+------------------
        * 27       0026.f064.0000    dynamic      -       F    F    po1
        * 27       001b.54c2.2644    dynamic      -       F    F    po1
        * 27       0000.0c9f.f2bc    dynamic      -       F    F    po1
        * 27       0026.980a.df44    dynamic      -       F    F    po1
        * 16       0050.56bb.0164    dynamic      -       F    F    po2
        * 13       90e2.ba5a.9f30    dynamic      -       F    F    eth1/2
        * 13       90e2.ba4b.fc78    dynamic      -       F    F    eth1/1
          39       0100.5e00.4b4b    igmp         0       F    F    Po1 Po2 Po22
          110      0100.5e00.0118    igmp         0       F    F    Po1 Po2
                                                                    Eth142/1/3 Eth112/1/5
                                                                    Eth112/1/6 Eth122/1/5

        """
        pass

    def _get_bgp_route_attr(self, destination, vrf, next_hop, ip_version=4):
        """
        BGP protocol attributes for get_route_tp
        Only IPv4 supported
        """
        pass

    def get_route_to(self, destination="", protocol="", longer=False):
        """
        Only IPv4 supported, vrf aware, longer_prefixes parameter ready
        """
        pass

    def get_snmp_information(self):
        pass

    def get_users(self):
        pass

    def get_vlans(self):
        pass

    def get_optics(self):
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
        """
        pass
