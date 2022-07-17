# Device
```
use pcap::Device;

fn main() {
    let mut cap = Device::list().unwrap();
    println!("{:?}", cap);
}
```
```
[
    Device {
        name: "enp4s0",
        desc: None,
        addresses: [
            Address {
                addr: 192.168.1.172,
                netmask: Some(255.255.255.0),
                broadcast_addr: Some(192.168.1.255),
                dst_addr: None
            },
            Address {
                addr: fe80::32a4:d4fc:63fe:c5db,
                netmask: Some(ffff:ffff:ffff:ffff::),
                broadcast_addr: None,
                dst_addr: None 
            }
        ] 
    },
    Device {
        name: "lo",
        desc: None,
        addresses: [
            Address {
                addr: 127.0.0.1,
                netmask: Some(255.0.0.0),
                broadcast_addr: None,
                dst_addr: None
            }, 
            Address {
                addr: ::1,
                netmask: Some(ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff),
                broadcast_addr: None,
                dst_addr: None
            }
        ]
    },
    Device {
        name: "any",
        desc: Some("Pseudo-device that captures on all interfaces"),
        addresses: []
    },
    Device {
        name: "bluetooth-monitor",
        desc: Some("Bluetooth Linux Monitor"),
        addresses: []
    }, 
    Device {
        name: "nflog",
        desc: Some("Linux netfilter log (NFLOG) interface"),
        addresses: []
    }, 
    Device {
        name: "nfqueue",
        desc: Some("Linux netfilter queue (NFQUEUE) interface"),
        addresses: []
    }
]
```
```
root@slava-tower:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 04:42:1a:96:a6:c9 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.172/24 brd 192.168.1.255 scope global dynamic noprefixroute enp4s0
       valid_lft 80002sec preferred_lft 80002sec
    inet6 fe80::32a4:d4fc:63fe:c5db/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```