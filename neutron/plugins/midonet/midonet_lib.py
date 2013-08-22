# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2012 Midokura Japan K.K.
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
# @author: Tomoe Sugihara, Midokura Japan KK
# @author: Ryu Ishimoto, Midokura Japan KK


from webob import exc as w_exc

from neutron.common import exceptions as q_exc
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)

PREFIX = 'OS_SG_'
OS_FLOATING_IP_RULE_KEY = 'OS_FLOATING_IP'
OS_ROUTER_IN_CHAIN_NAME_FORMAT = 'OS_ROUTER_IN_%s'
OS_ROUTER_OUT_CHAIN_NAME_FORMAT = 'OS_ROUTER_OUT_%s'
OS_TENANT_ROUTER_RULE_KEY = 'OS_TENANT_ROUTER_RULE'
SNAT_RULE = 'SNAT'
SNAT_RULE_PROPERTY = {OS_TENANT_ROUTER_RULE_KEY: SNAT_RULE}


def _get_rule_addr(addr):
    nw_addr, nw_len = addr.split('/')
    nw_len = int(nw_len)
    return nw_addr, nw_len


def _get_protocol_value(protocol):
    p = protocol.lower()
    if p == 'tcp':
        return 6
    elif p == 'udp':
        return 17
    elif p == 'icmp':
        return 1
    else:
        raise ValueError("Unsupported protocol: %s" % protocol)


def _get_ethertype_value(ethertype):
    e = ethertype.lower()
    if e == 'ipv4':
        return 0x0800
    elif e == 'ipv6':
        return 0x86DD
    else:
        raise ValueError("Unsupported ethertype: %s" % ethertype)


def _subnet_str(cidr):
    """Convert the cidr string to x.x.x.x_y format

    :param cidr: CIDR in x.x.x.x/y format
    """
    return cidr.replace("/", "_")


def router_chain_names(router_id):
    in_name = OS_ROUTER_IN_CHAIN_NAME_FORMAT % router_id
    out_name = OS_ROUTER_OUT_CHAIN_NAME_FORMAT % router_id
    return {'in': in_name, 'out': out_name}


def handle_api_error(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except w_exc.HTTPException as ex:
            raise MidonetApiException(msg=ex)
    return wrapped


class MidonetResourceNotFound(q_exc.NotFound):
    message = _('MidoNet %(resource_type)s %(id)s could not be found')


class MidonetApiException(q_exc.NeutronException):
    message = _("MidoNet API error: %(msg)s")


class MidoClient:

    def __init__(self, mido_api):
        self.mido_api = mido_api

    @handle_api_error
    def create_bridge(self, tenant_id, name):
        """Create a new bridge

        :param tenant_id: id of tenant creating the bridge
        :param name: name of the bridge
        :returns: newly created bridge
        """
        LOG.debug(_("MidoClient.create_bridge called: "
                    "tenant_id=%(tenant_id)s, name=%(name)s"),
                  {'tenant_id': tenant_id, 'name': name})
        return self.mido_api.add_bridge().name(name).tenant_id(
            tenant_id).create()

    @handle_api_error
    def delete_bridge(self, id):
        """Delete a bridge

        :param id: id of the bridge
        """
        LOG.debug(_("MidoClient.delete_bridge called: id=%(id)s"), {'id': id})
        return self.mido_api.delete_bridge(id)

    @handle_api_error
    def get_bridge(self, id):
        """Get a bridge

        :param id: id of the bridge
        :returns: requested bridge. None if bridge does not exist.
        """
        LOG.debug(_("MidoClient.get_bridge called: id=%s"), id)
        try:
            return self.mido_api.get_bridge(id)
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Bridge', id=id)

    @handle_api_error
    def update_bridge(self, id, name):
        """Update a bridge of the given id with the new name

        :param id: id of the bridge
        :param name: name of the bridge to set to
        :returns: bridge object
        """
        LOG.debug(_("MidoClient.update_bridge called: "
                    "id=%(id)s, name=%(name)s"), {'id': id, 'name': name})
        try:
            return self.mido_api.get_bridge(id).name(name).update()
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Bridge', id=id)

    @handle_api_error
    def create_dhcp(self, bridge, gateway_ip, net_addr, net_len):
        """Create a new DHCP entry

        :param bridge: bridge object to add dhcp to
        :param gateway_ip: IP address of gateway
        :param net_addr: network IP address
        :param net_len: network IP address length
        :returns: newly created dhcp
        """
        LOG.debug(_("MidoClient.create_dhcp called: bridge=%(bridge)s, "
                    "net_addr=%(net_addr)s, net_len=%(net_len)s, "
                    "gateway_ip=%(gateway_ip)s"),
                  {'bridge': bridge, 'net_addr': net_addr, 'net_len': net_len,
                   'gateway_ip': gateway_ip})
        return bridge.add_dhcp_subnet().default_gateway(
            gateway_ip).subnet_prefix(net_addr).subnet_length(
                net_len).create()

    @handle_api_error
    def add_dhcp_host(self, bridge, cidr, ip, mac):
        """Add DHCP host entry

        :param bridge: bridge the DHCP is configured for
        :param cidr: subnet represented as x.x.x.x/y
        :param ip: IP address
        :param mac: MAC address
        """
        LOG.debug(_("MidoClient.add_dhcp_host called: bridge=%(bridge)s, "
                    "cidr=%(cidr)s, ip=%(ip)s, mac=%(mac)s"),
                  {'bridge': bridge, 'cidr': cidr, 'ip': ip, 'mac': mac})
        subnet = bridge.get_dhcp_subnet(_subnet_str(cidr))
        if subnet is None:
            raise MidonetApiException(msg="Tried to add to non-existent DHCP")

        subnet.add_dhcp_host().ip_addr(ip).mac_addr(mac).create()

    @handle_api_error
    def remove_dhcp_host(self, bridge, cidr, ip, mac):
        """Remove DHCP host entry

        :param bridge: bridge the DHCP is configured for
        :param cidr: subnet represented as x.x.x.x/y
        :param ip: IP address
        :param mac: MAC address
        """
        LOG.debug(_("MidoClient.remove_dhcp_host called: bridge=%(bridge)s, "
                    "cidr=%(cidr)s, ip=%(ip)s, mac=%(mac)s"),
                  {'bridge': bridge, 'cidr': cidr, 'ip': ip, 'mac': mac})
        subnet = bridge.get_dhcp_subnet(_subnet_str(cidr))
        if subnet is None:
            LOG.warn(_("Tried to delete mapping from non-existent subnet"))
            return

        for dh in subnet.get_dhcp_hosts():
            if dh.get_mac_addr() == mac and dh.get_ip_addr() == ip:
                LOG.debug(_("MidoClient.remove_dhcp_host: Deleting %(dh)r"),
                          {"dh": dh})
                dh.delete()

    @handle_api_error
    def delete_dhcp_host(self, bridge_id, cidr, ip, mac):
        """Delete DHCP host entry

        :param bridge_id: id of the bridge of the DHCP
        :param cidr: subnet represented as x.x.x.x/y
        :param ip: IP address
        :param mac: MAC address
        """
        LOG.debug(_("MidoClient.delete_dhcp_host called: "
                    "bridge_id=%(bridge_id)s, cidr=%(cidr)s, ip=%(ip)s, "
                    "mac=%(mac)s"), {'bridge_id': bridge_id,
                                     'cidr': cidr,
                                     'ip': ip, 'mac': mac})
        bridge = self.get_bridge(bridge_id)
        self.remove_dhcp_host(bridge, _subnet_str(cidr), ip, mac)

    @handle_api_error
    def delete_dhcp(self, bridge):
        """Delete a DHCP entry

        :param bridge: bridge to remove DHCP from
        """
        LOG.debug(_("MidoClient.delete_dhcp called: bridge=%(bridge)s, "),
                  {'bridge': bridge})
        dhcp = bridge.get_dhcp_subnets()
        if not dhcp:
            raise MidonetApiException(msg="Tried to delete non-existent DHCP")
        dhcp[0].delete()

    @handle_api_error
    def delete_port(self, id):
        """Delete a port

        :param id: id of the port
        """
        LOG.debug(_("MidoClient.delete_port called: id=%(id)s"), {'id': id})
        self.mido_api.delete_port(id)

    @handle_api_error
    def get_port(self, id):
        """Get a port

        :param id: id of the port
        :returns: requested port. None if it does not exist
        """
        LOG.debug(_("MidoClient.get_port called: id=%(id)s"), {'id': id})
        try:
            return self.mido_api.get_port(id)
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Port', id=id)

    @handle_api_error
    def add_bridge_port(self, bridge):
        """Add a port on a bridge

        :param bridge: Bridge to add a new port to
        :returns: newly created port
        """
        LOG.debug(_("MidoClient.add_bridge_port called: "
                    "bridge=%(bridge)s"), {'bridge': bridge})
        return bridge.add_port().create()

    @handle_api_error
    def create_router(self, tenant_id, name):
        """Create a new router

        :param tenant_id: id of tenant creating the router
        :param name: name of the router
        :returns: newly created router
        """
        LOG.debug(_("MidoClient.create_router called: "
                    "tenant_id=%(tenant_id)s, name=%(name)s"),
                  {'tenant_id': tenant_id, 'name': name})
        return self.mido_api.add_router().name(name).tenant_id(
            tenant_id).create()

    @handle_api_error
    def create_tenant_router(self, tenant_id, name):
        """Create a new tenant router

        :param tenant_id: id of tenant creating the router
        :param name: name of the router
        :returns: newly created router
        """
        LOG.debug(_("MidoClient.create_tenant_router called: "
                    "tenant_id=%(tenant_id)s, name=%(name)s"),
                  {'tenant_id': tenant_id, 'name': name})
        router = self.create_router(tenant_id, name)
        self.create_router_chains(router)
        return router

    @handle_api_error
    def delete_tenant_router(self, id):
        """Delete a tenant router

        :param id: id of router
        """
        LOG.debug(_("MidoClient.delete_tenant_router called: "
                    "id=%(id)s"), {'id': id})
        self.destroy_router_chains(id)

        # delete the router
        self.delete_router(id)

    @handle_api_error
    def delete_router(self, id):
        """Delete a router

        :param id: id of the router
        """
        LOG.debug(_("MidoClient.delete_router called: id=%(id)s"), {'id': id})
        return self.mido_api.delete_router(id)

    @handle_api_error
    def get_router(self, id):
        """Get a router with the given id

        :param id: id of the router
        :returns: requested router object.  None if it does not exist.
        """
        LOG.debug(_("MidoClient.get_router called: id=%(id)s"), {'id': id})
        try:
            return self.mido_api.get_router(id)
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Router', id=id)

    @handle_api_error
    def update_router(self, id, name):
        """Update a router of the given id with the new name

        :param id: id of the router
        :param name: name of the router to set to
        :returns: router object
        """
        LOG.debug(_("MidoClient.update_router called: "
                    "id=%(id)s, name=%(name)s"), {'id': id, 'name': name})
        try:
            return self.mido_api.get_router(id).name(name).update()
        except w_exc.HTTPNotFound:
            raise MidonetResourceNotFound(resource_type='Router', id=id)

    @handle_api_error
    def add_dhcp_route_option(self, bridge, cidr, gw_ip, dst_ip):
        """Add Option121 route to subnet

        :param bridge: Bridge to add the option route to
        :param cidr: subnet represented as x.x.x.x/y
        :param gw_ip: IP address of the next hop
        :param dst: IP address of the destination, in x.x.x.x/y format
        """
        LOG.debug(_("MidoClient.add_dhcp_route_option called: "
                    "bridge=%(bridge)s, cidr=%(cidr)s, gw_ip=%(gw_ip)s"
                    "dst=%(dst)s"),
                  {"bridge": bridge, "cidr": cidr, "gw_ip": gw_ip, "dst": dst})
        subnet = bridge.get_dhcp_subnet(_subnet_str(cidr))
        if subnet is None:
            raise MidonetApiException(msg="Tried to access non-existent DHCP")
        prefix, length = dst.split("/")
        routes = [{'destinationPrefix': prefix, 'destinationLength': length,
                   'gatewayAddr': gw_ip}]
        subnet.opt121_routes(routes).update()

    @handle_api_error
    def link_bridge_port_to_router(self, port_id, router_id, gateway_ip,
                                   net_addr, net_len):
        """Link a tenant bridge port to the router

        :param port_id: port ID
        :param router_id: router id to link to
        :param gateway_ip: IP address of gateway
        :param net_addr: network IP address
        :param net_len: network IP address length
        """
        LOG.debug(_("MidoClient.link_bridge_port_to_router called: "
                    "port_id=%(port_id)s, router_id=%(router_id)s, "
                    "gateway_ip=%(gateway_ip)s net_addr=%(net_addr)s, "
                    "net_len=%(net_len)s"),
                  {'port_id': port_id, 'router_id': router_id,
                   'gateway_ip': gateway_ip, 'net_addr': net_addr,
                   'net_len': net_len})
        router = self.get_router(router_id)

        # create a port on the router
        in_port = router.add_port()
        router_port = in_port.port_address(gateway_ip).network_address(
            net_addr).network_length(net_len).create()

        br_port = self.get_port(port_id)
        router_port.link(br_port.get_id())

        # add a route for the subnet in the provider router
        router.add_route().type('Normal').src_network_addr(
            '0.0.0.0').src_network_length(0).dst_network_addr(
                net_addr).dst_network_length(net_len).weight(
                    100).next_hop_port(router_port.get_id()).create()

    @handle_api_error
    def unlink_bridge_port_from_router(self, port_id, net_addr, net_len):
        """Unlink a tenant bridge port from the router

        :param bridge_id: bridge ID
        :param net_addr: network IP address
        :param net_len: network IP address length
        """
        LOG.debug(_("MidoClient.unlink_bridge_port_from_router called: "
                    "port_id=%(port_id)s, net_addr=%(net_addr)s, "
                    "net_len=%(net_len)s"),
                  {'port_id': port_id, 'net_addr': net_addr,
                   'net_len': net_len})
        port = self.get_port(port_id)
        port.unlink()
        self.delete_port(port.get_peer_id())
        self.delete_port(port.get_id())

    @handle_api_error
    def link_bridge_to_provider_router(self, bridge, provider_router,
                                       gateway_ip, net_addr, net_len):
        """Link a tenant bridge to the provider router

        :param bridge: tenant bridge
        :param provider_router: provider router to link to
        :param gateway_ip: IP address of gateway
        :param net_addr: network IP address
        :param net_len: network IP address length
        """
        LOG.debug(_("MidoClient.link_bridge_to_provider_router called: "
                    "bridge=%(bridge)s, provider_router=%(provider_router)s, "
                    "gateway_ip=%(gateway_ip)s, net_addr=%(net_addr)s, "
                    "net_len=%(net_len)s"),
                  {'bridge': bridge, 'provider_router': provider_router,
                   'gateway_ip': gateway_ip, 'net_addr': net_addr,
                   'net_len': net_len})
        # create a port on the provider router
        in_port = provider_router.add_port()
        pr_port = in_port.port_address(gateway_ip).network_address(
            net_addr).network_length(net_len).create()

        # create a bridge port, then link it to the router.
        br_port = bridge.add_port().create()
        pr_port.link(br_port.get_id())

        # add a route for the subnet in the provider router
        provider_router.add_route().type('Normal').src_network_addr(
            '0.0.0.0').src_network_length(0).dst_network_addr(
                net_addr).dst_network_length(net_len).weight(
                    100).next_hop_port(pr_port.get_id()).create()

    @handle_api_error
    def unlink_bridge_from_provider_router(self, bridge, provider_router):
        """Unlink a tenant bridge from the provider router

        :param bridge: tenant bridge
        :param provider_router: provider router to link to
        """
        LOG.debug(_("MidoClient.unlink_bridge_from_provider_router called: "
                    "bridge=%(bridge)s, provider_router=%(provider_router)s"),
                  {'bridge': bridge, 'provider_router': provider_router})
        # Delete routes and unlink the router and the bridge.
        routes = provider_router.get_routes()

        bridge_ports_to_delete = [
            p for p in provider_router.get_peer_ports()
            if p.get_device_id() == bridge.get_id()]

        for p in bridge.get_peer_ports():
            if p.get_device_id() == provider_router.get_id():
                # delete the routes going to the bridge
                for r in routes:
                    if r.get_next_hop_port() == p.get_id():
                        self.mido_api.delete_route(r.get_id())
                p.unlink()
                self.mido_api.delete_port(p.get_id())

        # delete bridge port
        for port in bridge_ports_to_delete:
            self.mido_api.delete_port(port.get_id())

    @handle_api_error
    def set_router_external_gateway(self, id, provider_router, snat_ip):
        """Set router external gateway

        :param ID: ID of the tenant router
        :param provider_router: provider router
        :param snat_ip: SNAT IP address
        """
        LOG.debug(_("MidoClient.set_router_external_gateway called: "
                    "id=%(id)s, provider_router=%(provider_router)s, "
                    "snat_ip=%(snat_ip)s)"),
                  {'id': id, 'provider_router': provider_router,
                   'snat_ip': snat_ip})
        tenant_router = self.get_router(id)

        # Create a port in the provider router
        in_port = provider_router.add_port()
        pr_port = in_port.network_address(
            '169.254.255.0').network_length(30).port_address(
                '169.254.255.1').create()

        # Create a port in the tenant router
        tr_port = tenant_router.add_port().network_address(
            '169.254.255.0').network_length(30).port_address(
                '169.254.255.2').create()

        # Link them
        pr_port.link(tr_port.get_id())

        # Add a route for snat_ip to bring it down to tenant
        provider_router.add_route().type(
            'Normal').src_network_addr('0.0.0.0').src_network_length(
                0).dst_network_addr(snat_ip).dst_network_length(
                    32).weight(100).next_hop_port(
                        pr_port.get_id()).create()

        # Add default route to uplink in the tenant router
        tenant_router.add_route().type('Normal').src_network_addr(
            '0.0.0.0').src_network_length(0).dst_network_addr(
                '0.0.0.0').dst_network_length(0).weight(
                    100).next_hop_port(tr_port.get_id()).create()

        # ADD SNAT(masquerade) rules
        chains = self.get_router_chains(
            tenant_router.get_tenant_id(), tenant_router.get_id())

        chains['in'].add_rule().nw_dst_address(snat_ip).nw_dst_length(
            32).type('rev_snat').flow_action('accept').in_ports(
                [tr_port.get_id()]).properties(
                    SNAT_RULE_PROPERTY).position(1).create()

        nat_targets = []
        nat_targets.append(
            {'addressFrom': snat_ip, 'addressTo': snat_ip,
             'portFrom': 1, 'portTo': 65535})

        chains['out'].add_rule().type('snat').flow_action(
            'accept').nat_targets(nat_targets).out_ports(
                [tr_port.get_id()]).properties(
                    SNAT_RULE_PROPERTY).position(1).create()

    @handle_api_error
    def clear_router_external_gateway(self, id):
        """Clear router external gateway

        :param ID: ID of the tenant router
        """
        LOG.debug(_("MidoClient.clear_router_external_gateway called: "
                    "id=%(id)s"), {'id': id})
        tenant_router = self.get_router(id)

        # delete the port that is connected to provider router
        for p in tenant_router.get_ports():
            if p.get_port_address() == '169.254.255.2':
                peer_port_id = p.get_peer_id()
                p.unlink()
                self.mido_api.delete_port(peer_port_id)
                self.mido_api.delete_port(p.get_id())

        # delete default route
        for r in tenant_router.get_routes():
            if (r.get_dst_network_addr() == '0.0.0.0' and
                    r.get_dst_network_length() == 0):
                self.mido_api.delete_route(r.get_id())

        # delete SNAT(masquerade) rules
        chains = self.get_router_chains(
            tenant_router.get_tenant_id(),
            tenant_router.get_id())

        for r in chains['in'].get_rules():
            if OS_TENANT_ROUTER_RULE_KEY in r.get_properties():
                if r.get_properties()[OS_TENANT_ROUTER_RULE_KEY] == SNAT_RULE:
                    self.mido_api.delete_rule(r.get_id())

        for r in chains['out'].get_rules():
            if OS_TENANT_ROUTER_RULE_KEY in r.get_properties():
                if r.get_properties()[OS_TENANT_ROUTER_RULE_KEY] == SNAT_RULE:
                    self.mido_api.delete_rule(r.get_id())

    @handle_api_error
    def get_router_chains(self, tenant_id, router_id):
        """Get router chains.

        Returns a dictionary that has in/out chain resources key'ed with 'in'
        and 'out' respectively, given the tenant_id and the router_id passed
        in in the arguments.
        """
        LOG.debug(_("MidoClient.get_router_chains called: "
                    "tenant_id=%(tenant_id)s router_id=%(router_id)s"),
                  {'tenant_id': tenant_id, 'router_id': router_id})

        chain_names = router_chain_names(router_id)
        chains = {}
        for c in self.mido_api.get_chains({'tenant_id': tenant_id}):
            if c.get_name() == chain_names['in']:
                chains['in'] = c
            elif c.get_name() == chain_names['out']:
                chains['out'] = c
        return chains

    @handle_api_error
    def create_router_chains(self, router):
        """Create chains for a new router.

        Creates chains for the router and returns the same dictionary as
        get_router_chains() returns.

        :param router: router to set chains for
        """
        LOG.debug(_("MidoClient.create_router_chains called: "
                    "router=%(router)s"), {'router': router})
        chains = {}
        router_id = router.get_id()
        tenant_id = router.get_tenant_id()
        chain_names = router_chain_names(router_id)
        chains['in'] = self.mido_api.add_chain().tenant_id(tenant_id).name(
            chain_names['in']).create()

        chains['out'] = self.mido_api.add_chain().tenant_id(tenant_id).name(
            chain_names['out']).create()

        # set chains to in/out filters
        router.inbound_filter_id(
            chains['in'].get_id()).outbound_filter_id(
                chains['out'].get_id()).update()
        return chains

    @handle_api_error
    def destroy_router_chains(self, id):
        """Deletes chains of a router.

        :param id: router ID to delete chains of
        """
        LOG.debug(_("MidoClient.destroy_router_chains called: "
                    "id=%(id)s"), {'id': id})
        # delete corresponding chains
        router = self.get_router(id)
        chains = self.get_router_chains(router.get_tenant_id(), id)
        if 'in' in chains:
            self.mido_api.delete_chain(chains['in'].get_id())
        if 'out' in chains:
            self.mido_api.delete_chain(chains['out'].get_id())

    @handle_api_error
    def setup_floating_ip(self, router_id, provider_router, floating_ip,
                          fixed_ip, identifier):
        """Setup MidoNet for floating IP

        :param router_id: router_id
        :param provider_router: provider router
        :param floating_ip: floating IP address
        :param fixed_ip: fixed IP address
        :param identifier: identifier to use to map to MidoNet
        """
        LOG.debug(_("MidoClient.setup_floating_ip called: "
                    "router_id=%(router_id)s, "
                    "provider_router=%(provider_router)s"
                    "floating_ip=%(floating_ip)s, fixed_ip=%(fixed_ip)s"
                    "identifier=%(identifier)s"),
                  {'router_id': router_id, 'provider_router': provider_router,
                   'floating_ip': floating_ip, 'fixed_ip': fixed_ip,
                   'identifier': identifier})

        router = self.mido_api.get_router(router_id)
        # find the provider router port that is connected to the tenant
        # of the floating ip
        for p in router.get_peer_ports():
            if p.get_device_id() == provider_router.get_id():
                pr_port = p

        # get the tenant router port id connected to provider router
        tr_port_id = pr_port.get_peer_id()

        # add a route for the floating ip to bring it to the tenant
        provider_router.add_route().type(
            'Normal').src_network_addr('0.0.0.0').src_network_length(
                0).dst_network_addr(
                    floating_ip).dst_network_length(
                        32).weight(100).next_hop_port(
                            pr_port.get_id()).create()

        chains = self.get_router_chains(router.get_tenant_id(), router_id)

        # add dnat/snat rule pair for the floating ip
        nat_targets = []
        nat_targets.append(
            {'addressFrom': fixed_ip, 'addressTo': fixed_ip,
             'portFrom': 0, 'portTo': 0})

        floating_property = {OS_FLOATING_IP_RULE_KEY: identifier}
        chains['in'].add_rule().nw_dst_address(
            floating_ip).nw_dst_length(32).type(
                'dnat').flow_action('accept').nat_targets(
                    nat_targets).in_ports([tr_port_id]).position(
                        1).properties(floating_property).create()

        nat_targets = []
        nat_targets.append(
            {'addressFrom': floating_ip, 'addressTo': floating_ip,
             'portFrom': 0, 'portTo': 0})

        chains['out'].add_rule().nw_src_address(
            fixed_ip).nw_src_length(32).type(
                'snat').flow_action('accept').nat_targets(
                    nat_targets).out_ports(
                        [tr_port_id]).position(1).properties(
                            floating_property).create()

    @handle_api_error
    def clear_floating_ip(self, router_id, provider_router, floating_ip,
                          identifier):
        """Remove floating IP

        :param router_id: router_id
        :param provider_router: provider router
        :param floating_ip: floating IP address
        :param identifier: identifier to use to map to MidoNet
        """
        LOG.debug(_("MidoClient.clear_floating_ip called: "
                    "router_id=%(router_id)s, "
                    "provider_router=%(provider_router)s"
                    "floating_ip=%(floating_ip)s, identifier=%(identifier)s"),
                  {'router_id': router_id, 'provider_router': provider_router,
                   'floating_ip': floating_ip, 'identifier': identifier})
        router = self.mido_api.get_router(router_id)

        # find the provider router port that is connected to the tenant
        # delete the route for this floating ip
        for r in provider_router.get_routes():
            if (r.get_dst_network_addr() == floating_ip and
                    r.get_dst_network_length() == 32):
                self.mido_api.delete_route(r.get_id())

        # delete snat/dnat rule pair for this floating ip
        chains = self.get_router_chains(router.get_tenant_id(), router_id)

        for r in chains['in'].get_rules():
            if OS_FLOATING_IP_RULE_KEY in r.get_properties():
                if r.get_properties()[OS_FLOATING_IP_RULE_KEY] == identifier:
                    LOG.debug(_('deleting rule=%r'), r)
                    self.mido_api.delete_rule(r.get_id())
                    break

        for r in chains['out'].get_rules():
            if OS_FLOATING_IP_RULE_KEY in r.get_properties():
                if r.get_properties()[OS_FLOATING_IP_RULE_KEY] == identifier:
                    LOG.debug(_('deleting rule=%r'), r)
                    self.mido_api.delete_rule(r.get_id())
                    break

    @handle_api_error
    def create_chain(self, tenant_id, name):
        """Create a new chain"""
        LOG.debug(_("MidoClient.create_chain called: tenant_id=%(tenant_id)s "
                    " name=%(name)s"), {"tenant_id": tenant_id, "name": name})
        return self.mido_api.add_chain().tenant_id(tenant_id).name(
            name).create()

    @handle_api_error
    def delete_chains_by_names(self, tenant_id, names):
        """Delete chains matching the names given for a tenant
        """
        LOG.debug(_("MidoClient.delete_chains_by_names called: "
                    "tenant_id=%(tenant_id)s names=%(names)s "),
                  {"tenant_id": tenant_id, "names": names})
        chains = self.mido_api.get_chains({'tenant_id': tenant_id})
        for c in chains:
            if c.get_name() in names:
                LOG.debug(_("Deleting chain %(id)s"), {"id": c.get_id()})
                self.mido_api.delete_chain(c.get_id())

    @handle_api_error
    def get_chain_by_name(self, tenant_id, name):
        """Get the chain by its name."""
        LOG.debug(_("MidoClient.get_chain_by_name called: "
                    "tenant_id=%(tenant_id)s name=%(name)s "),
                  {"tenant_id": tenant_id, "name": name})
        for c in self.mido_api.get_chains({'tenant_id': tenant_id}):
            if c.get_name() == name:
                return c
        return None

    @handle_api_error
    def get_port_group_by_name(self, tenant_id, name):
        """Get the port group by name."""
        LOG.debug(_("MidoClient.get_port_group_by_name called: "
                    "tenant_id=%(tenant_id)s name=%(name)s "),
                  {"tenant_id": tenant_id, "name": name})
        for p in self.mido_api.get_port_groups({'tenant_id': tenant_id}):
            if p.get_name() == name:
                return p
        return None

    @handle_api_error
    def create_port_group(self, tenant_id, name):
        """Create a port group

        Create a new port group for a given name and ID.
        """
        LOG.debug(_("MidoClient.create_port_group called: "
                    "tenant_id=%(tenant_id)s name=%(name)s"),
                  {"tenant_id": tenant_id, "name": name})
        return self.mido_api.add_port_group().tenant_id(tenant_id).name(
            name).create()

    @handle_api_error
    def delete_port_group_by_name(self, tenant_id, name):
        """Delete port group matching the name given for a tenant
        """
        LOG.debug(_("MidoClient.delete_port_group_by_name called: "
                    "tenant_id=%(tenant_id)s name=%(name)s "),
                  {"tenant_id": tenant_id, "name": name})
        pgs = self.mido_api.get_port_groups({'tenant_id': tenant_id})
        for pg in pgs:
            if pg.get_name() == name:
                LOG.debug(_("Deleting pg %(id)s"), {"id": pg.get_id()})
                self.mido_api.delete_port_group(pg.get_id())

    @handle_api_error
    def add_port_to_port_group_by_name(self, tenant_id, name, port_id):
        """Add a port to a port group with the given name.
        """
        LOG.debug(_("MidoClient.add_port_to_port_group_by_name called: "
                    "tenant_id=%(tenant_id)s name=%(name)s "
                    "port_id=%(port_id)s"),
                  {"tenant_id": tenant_id, "name": name, "port_id": port_id})
        pg = self.get_port_group_by_name(tenant_id, name)
        if pg is None:
            raise MidonetResourceNotFound(resource_type='PortGroup', id=name)

        pg = pg.add_port_group_port().port_id(port_id).create()
        return pg

    @handle_api_error
    def add_accept_chain_rule(self, chain, direction='inbound', pg_id=None,
                              addr=None, port_from=-1, port_to=-1,
                              protocol=None, ethertype=None, **kwargs):
        """Create a new accept chain rule.

        :param direction: Could be either 'inbound' or 'outbound'.
        :param pg_id: Port group ID
        :param addr: CIDR in the format x.x.x.x/y
        :param port_from: Start port number.  For ICMP, use this for type
        :param port_to: End port number. For ICMP use this for code
        :param protocol: Could be one of 'tcp', 'udp', or 'icmp'
        :param ethertype: Could be one of 'ipv4', 'ipv6'
        """
        LOG.debug(_("MidoClient.create_rule called: chain=%(chain)s "
                    "direction=%(direction)s, pg_id=%(pg_id)s, addr=%(addr)s, "
                    "port_from=%(port_from)s, port_to=%(port_to)s, "
                    "protocol=%(protocol)s, ethertype=%(ethertype)s"),
                  {"chain": chain, "direction": direction, "pg_id": pg_id,
                   "addr": addr, "port_from": port_from, "port_to": port_to,
                   "protocol": protocol, "ethertype": ethertype})

        if direction not in ["inbound", "outbound"]:
            raise ValueError("Invalid direction provided: %s" % direction)

        eth = None
        if ethertype:
            eth = _get_ethertype_value(ethertype)

        proto = None
        if protocol:
            proto = _get_protocol_value(protocol)

        rule = chain.add_rule().type("accept").nw_proto(proto).dl_type(
            eth).properties(kwargs)

        nw_addr = nw_len = None
        if addr:
            nw_addr, nw_len = _get_rule_addr(addr)

        if port_from < 0:
            port_from = None
        if port_to < 0:
            port_to = None

        tp = {"start": port_from, "end": port_to}
        if direction == "inbound":
            rule = rule.nw_dst_address(nw_addr).nw_dst_length(
                nw_len).port_group_dst(pg_id).tp_dst(tp)
        else:
            rule = rule.nw_src_address(nw_addr).nw_src_length(
                nw_len).port_group_src(pg_id).tp_src(tp)

        if proto == 1:  # ICMP
            # Overwrite port fields regardless of the direction
            tp_src = {"start": port_from, "end": port_from}
            tp_dst = {"start": port_to, "end": port_to}
            rule = rule.tp_src(tp_src).tp_dst(tp_dst)

        return rule.create()

    @handle_api_error
    def delete_rules_by_property(self, chain_id, key, value):
        LOG.debug(_("MidoClient.delete_rules_by_property called: "
                    "chain_id=%(chain_id)s, key=%(key)s, value=%(value)s"),
                  {"chain_id": chain_id, "key": key, "value": value})

        chain = self.mido_api.get_chain(chain_id)
        if chain is None:
            raise MidonetResourceNotFound(resource_type='Chain', id=chain_id)

        for r in chain.get_rules():
            props = r.get_properties()
            if not props or key not in props:
                continue

            if props[key] == value:
                self.mido_api.delete_rule(r.get_id())
