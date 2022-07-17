// use std::path::Path;

use pcap::{Device, Capture, Packet};
use pktparse;
use clap::Parser;

use pktparse::{
    ethernet::{EthernetFrame, parse_ethernet_frame, EtherType},
    ip::IPProtocol,
    ipv4::{IPv4Header, parse_ipv4_header},
    ipv6::{IPv6Header, parse_ipv6_header},
    udp::{UdpHeader, parse_udp_header},
    tcp::{TcpHeader, parse_tcp_header},
};


/// A simple program for capturing and analyzing network card packets
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network interface
    #[clap(short, long, value_parser, default_value = "any")]
    interface: String,

    /// filter
    #[clap(short, long, value_parser, default_value = "tcp")]
    filter: String,

    /// Capture time in seconds
    #[clap(short, long, value_parser, default_value_t = 1)]
    capture: i32,
}


#[derive(Debug)]
struct Frame<'a> {
    eth: EthernetFrame,
    ip: IPv4Header,
    transport: THeader,
    data: &'a [u8],
}


#[derive(Debug)]
enum THeader {
    TCP(TcpHeader),
    UDP(UdpHeader),
}


fn find_device_by_name(find_name: Option<String>) -> Result<pcap::Device, &'static str> {
    let name: String = find_name.unwrap_or(String::from("any"));

    let interfaces = Device::list().unwrap();

    for interface in interfaces {
        println!("{:?}", interface);
        if interface.name == name {
            return Ok(interface);
        }
    }

    Err("Interface not found!")
}


fn parse_packet(packet: Packet) -> Result<Frame, &'static str> {
    let (_data, _eth) = parse_ethernet_frame(packet.data).unwrap();

    if _eth.ethertype != EtherType::IPv4 {
        return Err("Not IPv4 packet");
    }

    let (_data, _ip) = parse_ipv4_header(_data).unwrap();

    if _ip.protocol != IPProtocol::TCP && _ip.protocol != IPProtocol::UDP {
        return Err("Protocol not in (TCP, UDP)");
    }



    let (_data, _transport): (&[u8], THeader) = match _ip.protocol {
        IPProtocol::TCP => {
            let (_data, _tcp) = parse_tcp_header(_data).unwrap();
            (_data, THeader::TCP(_tcp))
        },
        IPProtocol::UDP => {
            let (_data, _udp) = parse_udp_header(_data).unwrap();
            (_data, THeader::UDP(_udp))
        },
        _ => return Err("Cannot parse protocol headers!")
    };

    Ok(Frame{
        eth: _eth,
        ip: _ip,
        transport: _transport,
        data: _data
    })
}


fn main() {
    let args = Args::parse();
    println!("{:?}", args);

    let dev = find_device_by_name(Some(String::from(args.interface))).unwrap();
    let cap = Capture::from_device(dev).unwrap();

    let mut cap = cap.timeout(1000)
                     .promisc(true)
                     .open()
                     .unwrap();

    cap.filter(&args.filter[..], false).unwrap();

    for _ in 1..100 {
        let packet = cap.next().unwrap();
        let data = parse_packet(packet);
        println!("{:?}", data.unwrap());        
    }

}