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
# @author: Takaaki Suzuki, Midokura Japan KK
# @author: Tomoe Sugihara, Midokura Japan KK
# @author: Ryu Ishimoto, Midokura Japan KK

from midonetclient import api
from oslo.config import cfg

from neutron.common import constants
from neutron.common import exceptions as q_exc
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.plugins.midonet import config  # noqa
from neutron.plugins.midonet import midonet_lib

LOG = logging.getLogger(__name__)


METADATA_DEFAULT_IP = "169.254.169.254/32"
OS_SG_RULE_KEY = 'os_sg_rule_id'
SG_INGRESS_CHAIN_NAME = "OS_SG_%s_INGRESS"
SG_EGRESS_CHAIN_NAME = "OS_SG_%s_EGRESS"
SG_PORT_GROUP_NAME = "OS_PG_%s"


def sg_chain_names(sg_id):
    ingress = SG_INGRESS_CHAIN_NAME % sg_id
    egress = SG_EGRESS_CHAIN_NAME % sg_id
    return {'ingress': ingress, 'egress': egress}


def sg_port_group_name(sg_id):
    return SG_PORT_GROUP_NAME % sg_id


def _rule_direction(sg_direction):
    if sg_direction == 'ingress':
        return 'outbound'
    elif sg_direction == 'egress':
        return 'inbound'
    else:
        raise ValueError(_("Unrecognized direction %s"), sg_direction)


def _is_vif_port(port):
    """Check whether the given port is a standard VIF port

    :param port: port to check
    """
    device_owner = port['device_owner']
    return (device_owner != l3_db.DEVICE_OWNER_ROUTER_GW and
            device_owner != l3_db.DEVICE_OWNER_ROUTER_INTF)


def _is_dhcp_port(port):
    """Check whether the given port is a DHCP port

    :param port: port to check
    """
    device_owner = port['device_owner']
    return device_owner.startswith('network:dhcp')


def _check_resource_exists(func, id, name, raise_exc=False):
    try:
        func(id)
    except midonet_lib.MidonetResourceNotFound as exc:
        LOG.error(_("There is no %(name)s with ID %(id)s in MidoNet."),
                  {"name": name, "id": id})
        if raise_exc:
            raise MidonetPluginException(msg=exc)


class MidoRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin):
    RPC_API_VERSION = '1.1'

    def __init__(self):
        pass

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        This a basic implementation that will call the plugin like get_ports
        and handle basic events
        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class MidonetPluginException(q_exc.NeutronException):
    message = _("%(msg)s")


class MidonetPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                      l3_db.L3_NAT_db_mixin,
                      agentschedulers_db.AgentSchedulerDbMixin,
                      securitygroups_db.SecurityGroupDbMixin):

    supported_extension_aliases = ['router', 'security-group']
    __native_bulk_support = False

    def __init__(self):

        # Read config values
        midonet_conf = cfg.CONF.MIDONET
        midonet_uri = midonet_conf.midonet_uri
        admin_user = midonet_conf.username
        admin_pass = midonet_conf.password
        admin_project_id = midonet_conf.project_id
        provider_router_id = midonet_conf.provider_router_id
        mode = midonet_conf.mode

        self.mido_api = api.MidonetApi(midonet_uri, admin_user,
                                       admin_pass,
                                       project_id=admin_project_id)
        self.client = midonet_lib.MidoClient(self.mido_api)

        if provider_router_id:
            self.provider_router = self.client.get_router(provider_router_id)
        else:
            msg = _('provider_router_id should be configured in the plugin '
                    'config file')
            LOG.exception(msg)
            raise MidonetPluginException(msg=msg)

        self.setup_rpc()
        db.configure_db()

    def setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.callbacks = MidoRpcCallbacks()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def create_subnet(self, context, subnet):
        """Create Neutron subnet.

        Creates a Neutron subnet and a DHCP entry in MidoNet bridge.
        """
        LOG.debug(_("MidonetPluginV2.create_subnet called: subnet=%r"), subnet)

        net = super(MidonetPluginV2, self).get_network(
            context, subnet['subnet']['network_id'], fields=None)

        session = context.session
        with session.begin(subtransactions=True):
            sn_entry = super(MidonetPluginV2, self).create_subnet(context,
                                                                  subnet)
            bridge = self.client.get_bridge(sn_entry['network_id'])

            gateway_ip = subnet['subnet']['gateway_ip']
            network_address, prefix = subnet['subnet']['cidr'].split('/')
            self.client.create_dhcp(bridge, gateway_ip, network_address,
                                    prefix)

            # For external network, link the bridge to the provider router.
            if net['router:external']:
                gateway_ip = sn_entry['gateway_ip']
                network_address, length = sn_entry['cidr'].split('/')

                self.client.link_bridge_to_provider_router(
                    bridge, self.provider_router, gateway_ip, network_address,
                    length)

        LOG.debug(_("MidonetPluginV2.create_subnet exiting: sn_entry=%r"),
                  sn_entry)
        return sn_entry

    def delete_subnet(self, context, id):
        """Delete Neutron subnet.

        Delete neutron network and its corresponding MidoNet bridge.
        """
        LOG.debug(_("MidonetPluginV2.delete_subnet called: id=%s"), id)
        subnet = super(MidonetPluginV2, self).get_subnet(context, id,
                                                         fields=None)
        net = super(MidonetPluginV2, self).get_network(context,
                                                       subnet['network_id'],
                                                       fields=None)
        bridge = self.client.get_bridge(subnet['network_id'])
        self.client.delete_dhcp(bridge)

        # If the network is external, clean up routes, links, ports.
        if net['router:external']:
            self.client.unlink_bridge_from_provider_router(
                bridge, self.provider_router)

        super(MidonetPluginV2, self).delete_subnet(context, id)
        LOG.debug(_("MidonetPluginV2.delete_subnet exiting"))

    def create_network(self, context, network):
        """Create Neutron network.

        Create a new Neutron network and its corresponding MidoNet bridge.
        """
        LOG.debug(_('MidonetPluginV2.create_network called: network=%r'),
                  network)
        tenant_id = self._get_tenant_id_for_create(context, network['network'])
        self._ensure_default_security_group(context, tenant_id)

        bridge = self.client.create_bridge(tenant_id,
                                           network['network']['name'])
        network['network']['id'] = bridge.get_id()

        session = context.session
        with session.begin(subtransactions=True):
            net = super(MidonetPluginV2, self).create_network(context, network)
            self._process_l3_create(context, net, network['network'])

        LOG.debug(_("MidonetPluginV2.create_network exiting: net=%r"), net)
        return net

    def update_network(self, context, id, network):
        """Update Neutron network.

        Update an existing Neutron network and its corresponding MidoNet
        bridge.
        """
        LOG.debug(_("MidonetPluginV2.update_network called: id=%(id)r, "
                    "network=%(network)r"), {'id': id, 'network': network})
        session = context.session
        with session.begin(subtransactions=True):
            net = super(MidonetPluginV2, self).update_network(
                context, id, network)
            self.client.update_bridge(id, net['name'])

        LOG.debug(_("MidonetPluginV2.update_network exiting: net=%r"), net)
        return net

    def get_network(self, context, id, fields=None):
        """Get Neutron network.

        Retrieves a Neutron network and its corresponding MidoNet bridge.
        """
        LOG.debug(_("MidonetPluginV2.get_network called: id=%(id)r, "
                    "fields=%(fields)r"), {'id': id, 'fields': fields})
        qnet = super(MidonetPluginV2, self).get_network(context, id, fields)
        self.client.get_bridge(id)

        LOG.debug(_("MidonetPluginV2.get_network exiting: qnet=%r"), qnet)
        return qnet

    def delete_network(self, context, id):
        """Delete a network and its corresponding MidoNet bridge."""
        LOG.debug(_("MidonetPluginV2.delete_network called: id=%r"), id)
        self.client.delete_bridge(id)
        try:
            super(MidonetPluginV2, self).delete_network(context, id)
        except Exception:
            LOG.error(_('Failed to delete neutron db, while Midonet bridge=%r'
                      'had been deleted'), id)
            raise

    def _dhcp_mappings(self, context, port):
        mac = port["mac_address"]
        for fixed_ip in port["fixed_ips"]:
            subnet = self._get_subnet(context, fixed_ip["subnet_id"])
            if subnet["ip_version"] == 6:
                # TODO handle IPv6
                continue
            yield subnet['cidr'], fixed_ip["ip_address"], mac

    def _metadata_subnets(self, context, port):
        for fixed_ip in port["fixed_ips"]:
            subnet = self._get_subnet(context, fixed_ip["subnet_id"])
            if subnet["ip_version"] == 6:
                continue
            yield subnet['cidr'], fixed_ip["ip_address"]

    def _bind_port_to_sgs(self, context, port, sg_ids):
        self._process_port_create_security_group(context, port, sg_ids)
        for sg_id in sg_ids:
            pg_name = sg_port_group_name(sg_id)
            self.client.add_port_to_port_group_by_name(port["tenant_id"],
                                                       pg_name, port["id"])

    def create_port(self, context, port):
        """Create a L2 port in Neutron/MidoNet."""
        LOG.debug(_("MidonetPluginV2.create_port called: port=%r"), port)

        port_data = port['port']

        # Create a bridge port in MidoNet and set the bridge port ID as the
        # port ID in Neutron.
        bridge = self.client.get_bridge(port_data["network_id"])
        bridge_port = self.client.add_bridge_port(bridge)
        port_data["id"] = bridge_port.get_id()
        try:
            session = context.session
            with session.begin(subtransactions=True):
                # Create a Neutron port
                new_port = super(MidonetPluginV2, self).create_port(context,
                                                                    port)
                port_data.update(new_port)

                # Bind security groups to the port
                port_data[ext_sg.SECURITYGROUPS] = (
                    self._get_security_groups_on_port(context, port))
                if port_data[ext_sg.SECURITYGROUPS]:
                    self._bind_port_to_sgs(context, port_data,
                                           port_data[ext_sg.SECURITYGROUPS])
        except Exception as ex:
            # Try removing the MidoNet port before raising an exception.
            with excutils.save_and_reraise_exception():
                LOG.error(_("Failed to create a port on network %(net_id)s: "
                            "%(err)s"),
                          {"net_id": port_data["network_id"], "err": ex})
                self.client.delete_port(bridge_port.get_id())

        try:
            if _is_dhcp_port(port_data):
                # For DHCP port, add a metadata route
                for cidr, ip in self._metadata_subnets(context, port_data):
                    self.client.add_dhcp_route_option(bridge, cidr, ip,
                                                      METADATA_DEFAULT_IP)
            elif _is_vif_port(port_data):
                # DHCP mapping is only for VIF ports
                for cidr, ip, mac in self._dhcp_mappings(context, port_data):
                    self.client.add_dhcp_host(bridge, cidr, ip, mac)
        except Exception as ex:
            LOG.error(_("Failed to configure DHCP for port %(port)s, %(err)s"),
                      {"port": port_data["id"], "err": ex})
            # DHCP update error sets the port to error state
            with context.session.begin(subtransactions=True):
                p = self._get_port(context, port_data["id"])
                port_data['status'] = constants.PORT_STATUS_ERROR
                p['status'] = port_data['status']
                context.session.add(p)

        LOG.debug(_("MidonetPluginV2.create_port exiting: port=%r"), port_data)
        return port_data

    def get_port(self, context, id, fields=None):
        """Retrieve port."""
        LOG.debug(_("MidonetPluginV2.get_port called: id=%(id)s "
                    "fields=%(fields)r"), {'id': id, 'fields': fields})
        port = super(MidonetPluginV2, self).get_port(context, id, fields)
        _check_resource_exists(self.client.get_port, id, "port")

        LOG.debug(_("MidonetPluginV2.get_port exiting: port=%r"), port)
        return port

    def get_ports(self, context, filters=None, fields=None):
        """List neutron ports and verify that they exist in MidoNet."""
        LOG.debug(_("MidonetPluginV2.get_ports called: filters=%(filters)s "
                    "fields=%(fields)r"),
                  {'filters': filters, 'fields': fields})
        ports = super(MidonetPluginV2, self).get_ports(context, filters,
                                                       fields)
        if ports:
            for port in ports:
                if 'security_gorups' in port:
                    self._extend_port_dict_security_group(context, port)
        return ports

    def delete_port(self, context, id, l3_port_check=True):
        """Delete a neutron port and corresponding MidoNet bridge port."""
        LOG.debug(_("MidonetPluginV2.delete_port called: id=%(id)s "
                    "l3_port_check=%(l3_port_check)r"),
                  {'id': id, 'l3_port_check': l3_port_check})
        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)

        port = self.get_port(context, id)
        self.client.delete_port(id)
        try:
            for cidr, ip, mac in self._dhcp_mappings(context, port):
                self.client.delete_dhcp_host(port["network_id"], cidr, ip,
                                             mac)
        except Exception:
            LOG.error(_("Failed to delete DHCP mapping for port %(id)s"),
                      {"id": id})

        super(MidonetPluginV2, self).delete_port(context, id)

    def create_router(self, context, router):
        LOG.debug(_("MidonetPluginV2.create_router called: router=%r"), router)

        tenant_id = self._get_tenant_id_for_create(context, router['router'])
        session = context.session
        with session.begin(subtransactions=True):
            mrouter = self.client.create_tenant_router(
                tenant_id, router['router']['name'])

            qrouter = super(MidonetPluginV2, self).create_router(context,
                                                                 router)

            # get entry from the DB and update 'id' with MidoNet router id.
            qrouter_entry = self._get_router(context, qrouter['id'])
            qrouter['id'] = mrouter.get_id()
            qrouter_entry.update(qrouter)

            LOG.debug(_("MidonetPluginV2.create_router exiting: qrouter=%r"),
                      qrouter)
            return qrouter

    def update_router(self, context, id, router):
        LOG.debug(_("MidonetPluginV2.update_router called: id=%(id)s "
                    "router=%(router)r"), router)

        op_gateway_set = False
        op_gateway_clear = False

        # figure out which operation it is in
        if ('external_gateway_info' in router['router'] and
                'network_id' in router['router']['external_gateway_info']):
            op_gateway_set = True
        elif ('external_gateway_info' in router['router'] and
              router['router']['external_gateway_info'] == {}):
            op_gateway_clear = True

            qports = super(MidonetPluginV2, self).get_ports(
                context, {'device_id': [id],
                          'device_owner': ['network:router_gateway']})

            assert len(qports) == 1
            qport = qports[0]
            snat_ip = qport['fixed_ips'][0]['ip_address']
            qport['network_id']

        session = context.session
        with session.begin(subtransactions=True):

            qrouter = super(MidonetPluginV2, self).update_router(context, id,
                                                                 router)

            changed_name = router['router'].get('name')
            if changed_name:
                self.client.update_router(id, changed_name)

            if op_gateway_set:
                # find a qport with the network_id for the router
                qports = super(MidonetPluginV2, self).get_ports(
                    context, {'device_id': [id],
                              'device_owner': ['network:router_gateway']})
                assert len(qports) == 1
                qport = qports[0]
                snat_ip = qport['fixed_ips'][0]['ip_address']

                self.client.set_router_external_gateway(id,
                                                        self.provider_router,
                                                        snat_ip)

            if op_gateway_clear:
                self.client.clear_router_external_gateway(id)

        LOG.debug(_("MidonetPluginV2.update_router exiting: qrouter=%r"),
                  qrouter)
        return qrouter

    def delete_router(self, context, id):
        LOG.debug(_("MidonetPluginV2.delete_router called: id=%s"), id)

        self.client.delete_tenant_router(id)

        result = super(MidonetPluginV2, self).delete_router(context, id)
        LOG.debug(_("MidonetPluginV2.delete_router exiting: result=%s"),
                  result)
        return result

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("MidonetPluginV2.add_router_interface called: "
                    "router_id=%(router_id)s "
                    "interface_info=%(interface_info)r"),
                  {'router_id': router_id, 'interface_info': interface_info})

        with context.session.begin(subtransactions=True):
            info = super(MidonetPluginV2, self).add_router_interface(
                context, router_id, interface_info)
            subnet = self._get_subnet(context, info["subnet_id"])

        try:
            # Link the router and the bridge
            self.client.link_bridge_to_router(info["port_id"], router_id,
                                              subnet["gateway_ip"],
                                              subnet["cidr"])
        except Exception:
            LOG.error(_("Failed to create MidoNet resources to add router "
                        "interface. info=%(info), router_id=%(router_id)"),
                      {"info": info, "router_id": router_id})
            with excutils.save_and_reraise_exception():
                with context.session.begin(subtransactions=True):
                    self.remove_router_interface(context, router_id, info)

        LOG.debug(_("MidonetPluginV2.add_router_interface exiting: "
                    "info=%r"), info)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        """Remove interior router ports."""
        LOG.debug(_("MidonetPluginV2.remove_router_interface called: "
                    "router_id=%(router_id)s "
                    "interface_info=%(interface_info)r"),
                  {'router_id': router_id, 'interface_info': interface_info})
        port_id = None
        if 'port_id' in interface_info:

            port_id = interface_info['port_id']
            subnet_id = self.get_port(context,
                                      interface_info['port_id']
                                      )['fixed_ips'][0]['subnet_id']

            subnet = self._get_subnet(context, subnet_id)

        if 'subnet_id' in interface_info:

            subnet_id = interface_info['subnet_id']
            subnet = self._get_subnet(context, subnet_id)
            network_id = subnet['network_id']

            # find a neutron port for the network
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=network_id)
            network_port = None
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    network_port = p
                    break
            assert network_port
            port_id = network_port['id']

        assert port_id

        # get network information from subnet data
        network_addr, network_length = subnet['cidr'].split('/')
        network_length = int(network_length)

        # Unlink the router and the bridge.
        self.client.unlink_bridge_port_from_router(port_id, network_addr,
                                                   network_length)

        info = super(MidonetPluginV2, self).remove_router_interface(
            context, router_id, interface_info)
        LOG.debug(_("MidonetPluginV2.remove_router_interface exiting"))
        return info

    def update_floatingip(self, context, id, floatingip):
        LOG.debug(_("MidonetPluginV2.update_floatingip called: id=%(id)s "
                    "floatingip=%(floatingip)s "),
                  {'id': id, 'floatingip': floatingip})

        session = context.session
        with session.begin(subtransactions=True):
            if floatingip['floatingip']['port_id']:
                fip = super(MidonetPluginV2, self).update_floatingip(
                    context, id, floatingip)

                self.client.setup_floating_ip(fip['router_id'],
                                              self.provider_router,
                                              fip['floating_ip_address'],
                                              fip['fixed_ip_address'], id)
            # disassociate floating IP
            elif floatingip['floatingip']['port_id'] is None:

                fip = super(MidonetPluginV2, self).get_floatingip(context, id)
                self.client.clear_floating_ip(fip['router_id'],
                                              self.provider_router,
                                              fip['floating_ip_address'], id)
                super(MidonetPluginV2, self).update_floatingip(context, id,
                                                               floatingip)

        LOG.debug(_("MidonetPluginV2.update_floating_ip exiting: fip=%s"), fip)
        return fip

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.

        Create a new security group, including the default security group.
        In MidoNet, this means creating a pair of chains, inbound and outbound,
        as well as a new port group.
        """
        LOG.debug(_("MidonetPluginV2.create_security_group called: "
                    "security_group=%(security_group)s "
                    "default_sg=%(default_sg)s "),
                  {'security_group': security_group, 'default_sg': default_sg})

        sg = security_group.get('security_group')
        tenant_id = self._get_tenant_id_for_create(context, sg)
        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)

        # Create the Neutron sg first
        sg = super(MidonetPluginV2, self).create_security_group(
            context, security_group, default_sg)

        try:
            # Process the MidoNet side
            self.client.create_port_group(tenant_id,
                                          sg_port_group_name(sg["id"]))
            chain_names = sg_chain_names(sg["id"])
            chains = {}
            for direction, chain_name in chain_names.iteritems():
                c = self.client.create_chain(tenant_id, chain_name)
                chains[direction] = c

            # Create all the rules for this SG.  Only accept rules are created
            for r in sg['security_group_rules']:
                self._create_accept_chain_rule(context, r,
                                               chain=chains[r['direction']])
        except Exception:
            LOG.error(_("Failed to create MidoNet resources for sg %(sg)r"),
                      {"sg": sg})
            with excutils.save_and_reraise_exception():
                with context.session.begin(subtransactions=True):
                    sg = self._get_security_group(context, sg["id"])
                    context.session.delete(sg)

        LOG.debug(_("MidonetPluginV2.create_security_group exiting: sg=%r"),
                  sg)
        return sg

    def delete_security_group(self, context, id):
        """Delete chains for Neutron security group."""
        LOG.debug(_("MidonetPluginV2.delete_security_group called: id=%s"), id)

        with context.session.begin(subtransactions=True):
            sg = super(MidonetPluginV2, self).get_security_group(context, id)
            if not sg:
                raise ext_sg.SecurityGroupNotFound(id=id)

            if sg["name"] == 'default' and not context.is_admin:
                raise ext_sg.SecurityGroupCannotRemoveDefault()

            sg_id = sg['id']
            filters = {'security_group_id': [sg_id]}
            if super(MidonetPluginV2, self)._get_port_security_group_bindings(
                    context, filters):
                raise ext_sg.SecurityGroupInUse(id=sg_id)

            # Delete MidoNet Chains and portgroup for the SG
            tenant_id = sg['tenant_id']
            self.client.delete_chains_by_names(
                tenant_id, sg_chain_names(sg["id"]).values())

            self.client.delete_port_group_by_name(tenant_id,
                                                  sg_port_group_name(sg["id"]))
            super(MidonetPluginV2, self).delete_security_group(context, id)

    def get_security_groups(self, context, filters=None, fields=None,
                            default_sg=False):
        LOG.debug(_("MidonetPluginV2.get_security_groups called: "
                    "filters=%(filters)r fields=%(fields)r"),
                  {'filters': filters, 'fields': fields})
        return super(MidonetPluginV2, self).get_security_groups(
            context, filters, fields, default_sg=default_sg)

    def get_security_group(self, context, id, fields=None, tenant_id=None):
        LOG.debug(_("MidonetPluginV2.get_security_group called: id=%(id)s "
                    "fields=%(fields)r tenant_id=%(tenant_id)s"),
                  {'id': id, 'fields': fields, 'tenant_id': tenant_id})
        return super(MidonetPluginV2, self).get_security_group(context, id,
                                                               fields)

    def _create_accept_chain_rule(self, context, sg_rule, chain=None):

        direction = sg_rule["direction"]
        tenant_id = sg_rule["tenant_id"]
        sg_id = sg_rule["security_group_id"]
        chain_name = sg_chain_names(sg_id)[direction]

        if chain is None:
            chain = self.client.get_chain_by_name(tenant_id, chain_name)

        pg_id = None
        if sg_rule["remote_group_id"] is not None:
            pg_name = sg_port_group_name(sg_id)
            pg = self.client.get_port_group_by_name(tenant_id, pg_name)
            pg_id = pg.get_id()

        props = {OS_SG_RULE_KEY: str(sg_rule["id"])}
        return self.client.add_accept_chain_rule(
            chain, _rule_direction(direction), pg_id,
            sg_rule["remote_ip_prefix"], sg_rule["port_range_min"],
            sg_rule["port_range_max"], sg_rule["protocol"],
            sg_rule["ethertype"], **props)

    def create_security_group_rule(self, context, security_group_rule):
        """Create a security group rule

        Create a security group rule in the Neutron DB and corresponding
        MidoNet resources in its data store.
        """
        LOG.debug(_("MidonetPluginV2.create_security_group_rule called: "
                    "security_group_rule=%(security_group_rule)r"),
                  {'security_group_rule': security_group_rule})

        with context.session.begin(subtransactions=True):
            rule = super(MidonetPluginV2, self).create_security_group_rule(
                context, security_group_rule)

            chain_rule = self._create_accept_chain_rule(context, rule)

            LOG.debug(_("MidonetPluginV2.create_security_group_rule exiting: "
                        "rule=%r"), rule)
            return rule

    def delete_security_group_rule(self, context, sg_rule_id):
        """Delete a security group rule

        Delete a security group rule from the Neutron DB and corresponding
        MidoNet resources from its data store.
        """
        LOG.debug(_("MidonetPluginV2.delete_security_group_rule called: "
                    "sg_rule_id=%s"), sg_rule_id)
        with context.session.begin(subtransactions=True):
            rule = super(MidonetPluginV2, self).get_security_group_rule(
                context, sg_rule_id)

            if not rule:
                raise ext_sg.SecurityGroupRuleNotFound(id=sg_rule_id)

            sg = self._get_security_group(context,
                                          rule["security_group_id"])
            chain_name = sg_chain_names(sg)[rule["direction"]]
            chain = self.client.get_chain_by_name(rule["tenant_id"],
                                                  chain_name)
            self.client.delete_rules_by_property(chain.get_id(),
                                                 OS_SG_RULE_KEY,
                                                 str(rule["id"]))
            super(MidonetPluginV2, self).delete_security_group_rule(context,
                                                                    sg_rule_id)
