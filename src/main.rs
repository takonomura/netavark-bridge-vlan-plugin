use ipnet::IpNet;
use netavark::{
    network::{
        core_utils::{
            add_default_routes, create_route_list, open_netlink_sockets, parse_option, CoreUtils,
        },
        netlink, types,
    },
    new_error,
    plugin::{Info, Plugin, PluginExec, API_VERSION},
};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_route::{
    link::{
        AfSpecBridge, BridgeVlanInfo, InfoData, InfoKind, InfoVeth, LinkAttribute, LinkMessage,
    },
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::{collections::HashMap, error::Error, net::IpAddr, os::fd::AsFd};

fn main() {
    let info = Info::new(
        env!("CARGO_PKG_VERSION").to_owned(),
        API_VERSION.to_owned(),
        None,
    );

    PluginExec::new(Exec {}, info).exec();
}

struct NetlinkSocket {
    socket: Socket,
    seq: u32,
    buf: [u8; 8192],
}

impl NetlinkSocket {
    fn new() -> Result<NetlinkSocket, Box<dyn Error>> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;

        Ok(NetlinkSocket {
            socket,
            seq: 0,
            buf: [0; 8192],
        })
    }

    fn request(&mut self, msg: RouteNetlinkMessage) -> Result<(), Box<dyn Error>> {
        let mut packet = NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::from(msg));
        packet.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        packet.header.sequence_number = self.seq;
        self.seq += 1;

        packet.finalize();
        let size = packet.header.length as usize;
        packet.serialize(&mut self.buf[..size]);

        self.socket.send(&self.buf[..size], 0)?;

        loop {
            let size = self.socket.recv(&mut &mut self.buf[..], 0)?;

            let mut offset = 0;
            loop {
                let packet: NetlinkMessage<RouteNetlinkMessage> =
                    NetlinkMessage::deserialize(&self.buf[offset..]).unwrap();

                match packet.payload {
                    NetlinkPayload::Done(_) => return Ok(()),
                    NetlinkPayload::Error(e) => {
                        if e.code.is_some() {
                            return Err(e.to_io().into());
                        } else {
                            return Ok(());
                        }
                    }
                    _ => {} // Ignore
                }

                offset += packet.header.length as usize;
                if offset == size || packet.header.length == 0 {
                    break;
                }
            }
        }
    }

    fn bridge_vlan_add(
        &mut self,
        link_id: u32,
        vlan_id: u16,
        tagged: bool,
    ) -> Result<(), Box<dyn Error>> {
        let mut info = BridgeVlanInfo::default();
        info.vid = vlan_id;
        if !tagged {
            info.flags = 6; // PVID(2) + UNTAGGED(4)
        }

        let mut msg = LinkMessage::default();
        msg.header.index = link_id;
        msg.header.interface_family = AddressFamily::Bridge;
        msg.attributes.push(LinkAttribute::AfSpecBridge(vec![
            AfSpecBridge::Flags(1), // MASTER(1)
            AfSpecBridge::VlanInfo(info),
        ]));

        self.request(RouteNetlinkMessage::SetLink(msg))
    }

    fn bridge_vlan_clear(&mut self, link_id: u32) -> Result<(), Box<dyn Error>> {
        let mut info = BridgeVlanInfo::default();
        info.vid = 1;
        info.flags = 6; // PVID(2) + UNTAGGED(4)

        let mut msg = LinkMessage::default();
        msg.header.index = link_id;
        msg.header.interface_family = AddressFamily::Bridge;
        msg.attributes.push(LinkAttribute::AfSpecBridge(vec![
            AfSpecBridge::Flags(1), // MASTER(1)
            AfSpecBridge::VlanInfo(info),
        ]));

        self.request(RouteNetlinkMessage::DelLink(msg))
    }
}

struct Exec {}

impl Plugin for Exec {
    fn create(&self, network: types::Network) -> Result<types::Network, Box<dyn Error>> {
        if network.network_interface.as_deref().unwrap_or_default() == "" {
            return Err(new_error!("no bridge interface name given"));
        }

        Ok(network)
    }

    fn setup(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<types::StatusBlock, Box<dyn Error>> {
        let (mut host, mut netns) = open_netlink_sockets(&netns)?;

        let bridge_name = opts.network.network_interface.unwrap_or_default();
        let interface_name = opts.network_options.interface_name;
        let static_mac = opts
            .network_options
            .static_mac
            .map(|mac| CoreUtils::decode_address_from_hex(&mac).unwrap());
        let mtu = parse_option(&opts.network.options, "mtu")?.unwrap_or(0);
        let metric = parse_option(&opts.network.options, "metric")?;
        let vlan = parse_option(&opts.network.options, "vlan")?;
        let tagged_vlans = opts
            .network
            .options
            .as_ref()
            .and_then(|opts| opts.get("tagged_vlans"))
            .map(|s| {
                s.split(",")
                    .map(|i| i.parse::<u16>())
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        // Create veth
        let mut peer_opts = netlink::CreateLinkOptions::new(interface_name.clone(), InfoKind::Veth);
        peer_opts.netns = Some(netns.file.as_fd());
        peer_opts.mac = static_mac.unwrap_or_default();
        peer_opts.mtu = mtu;
        let mut peer = LinkMessage::default();
        netlink::parse_create_link_options(&mut peer, peer_opts);
        let mut host_veth = netlink::CreateLinkOptions::new(String::from(""), InfoKind::Veth);
        let bridge = host.netlink.get_link(netlink::LinkID::Name(bridge_name))?;
        host_veth.primary_index = bridge.header.index; // primary: master device
        host_veth.info_data = Some(InfoData::Veth(InfoVeth::Peer(peer)));
        host_veth.mtu = mtu;
        host.netlink.create_link(host_veth)?;

        // Get link info
        let veth = netns
            .netlink
            .get_link(netlink::LinkID::Name(interface_name.clone()))?;
        let mac = veth
            .attributes
            .iter()
            .find_map(|nla| {
                if let LinkAttribute::Address(ref addr) = nla {
                    Some(CoreUtils::encode_address_to_hex(addr))
                } else {
                    None
                }
            })
            .unwrap();
        let host_link = veth
            .attributes
            .iter()
            .find_map(|nla| {
                if let LinkAttribute::Link(link) = nla {
                    Some(link)
                } else {
                    None
                }
            })
            .unwrap();

        if vlan.is_some() || tagged_vlans.is_some() {
            let mut socket = NetlinkSocket::new()?;
            socket.bridge_vlan_clear(*host_link)?;
            if let Some(vlan) = vlan {
                socket.bridge_vlan_add(*host_link, vlan, false)?;
            }
            for vlan in tagged_vlans.unwrap_or_default().into_iter() {
                socket.bridge_vlan_add(*host_link, vlan, true)?;
            }
        }

        // Set link up on host
        host.netlink.set_up(netlink::LinkID::ID(*host_link))?;

        // Add addresses
        let subnets = opts.network.subnets.unwrap_or_default();
        let mut addresses: Vec<types::NetAddress> = Vec::new();
        for addr in opts.network_options.static_ips.unwrap_or_default().iter() {
            let max_prefix_len = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            let subnet = subnets.iter().find(|s| s.subnet.contains(addr));
            let prefix_len = subnet
                .map(|subnet| subnet.subnet.prefix_len())
                .unwrap_or(max_prefix_len);
            let addr_with_net = IpNet::new(*addr, prefix_len)?;

            addresses.push(types::NetAddress {
                gateway: subnet.and_then(|s| s.gateway),
                ipnet: addr_with_net,
            });
            netns.netlink.add_addr(veth.header.index, &addr_with_net)?;
        }

        // Set link up in netns
        netns
            .netlink
            .set_up(netlink::LinkID::ID(veth.header.index))?;

        // Add default routes
        let gateways: Vec<IpNet> = subnets
            .iter()
            .filter_map(|subnet| {
                if let Some(gateway) = subnet.gateway {
                    Some(IpNet::new(gateway, subnet.subnet.prefix_len()).unwrap())
                } else {
                    None
                }
            })
            .collect();
        add_default_routes(&mut netns.netlink, &gateways, metric)?;

        // Add static routes
        for route in create_route_list(&opts.network.routes)?.iter() {
            netns.netlink.add_route(route)?;
        }

        Ok(types::StatusBlock {
            dns_server_ips: opts.network.network_dns_servers,
            dns_search_domains: Some(Vec::<String>::new()),
            interfaces: Some(HashMap::from([(
                interface_name,
                types::NetInterface {
                    mac_address: mac,
                    subnets: Some(addresses),
                },
            )])),
        })
    }

    fn teardown(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<(), Box<dyn Error>> {
        let (_host, mut netns) = open_netlink_sockets(&netns)?;

        for route in create_route_list(&opts.network.routes)?.iter() {
            netns.netlink.del_route(route)?;
        }

        let interface_name = opts.network_options.interface_name;
        netns
            .netlink
            .del_link(netlink::LinkID::Name(interface_name))?;

        Ok(())
    }
}
