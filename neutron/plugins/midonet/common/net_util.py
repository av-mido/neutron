# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2013 Midokura PTE LTD
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Ryu Ishimoto, Midokura Japan KK


from neutron.common import constants


def subnet_str(cidr):
    """Convert the cidr string to x.x.x.x_y format

    :param cidr: CIDR in x.x.x.x/y format
    """
    if cidr is None:
        return None
    return cidr.replace("/", "_")


def net_addr(addr):
    """Get network address prefix and length from a given address."""
    if addr is None:
        return (None, None)
    nw_addr, nw_len = addr.split('/')
    nw_len = int(nw_len)
    return nw_addr, nw_len


def get_ethertype_value(ethertype):
    """Connvert string representation of ethertype to the numerical."""
    if ethertype is None:
        return None
    e = ethertype.lower()
    if e == 'ipv4':
        return 0x0800
    elif e == 'ipv6':
        return 0x86DD
    elif e == 'arp':
        return 0x0806
    else:
        return None 


def get_protocol_value(protocol):
    """Convert string representation of protocol to the numerical."""
    if protocol is None:
        return None
    p = protocol.lower()
    if p == 'tcp':
        return constants.TCP_PROTOCOL
    elif p == 'udp':
        return constants.UDP_PROTOCOL
    elif p == 'icmp':
        return constants.ICMP_PROTOCOL
    else:
        return None 
