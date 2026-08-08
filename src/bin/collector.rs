use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::Serialize;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Debug)]
struct PacketLog {
    timestamp: u64,
    source_mac: String,
    dest_mac: String,
    source_ip: String,
    dest_ip: String,
    source_port: u16,
    dest_port: u16,
    protocol: String,
    packet_size: usize,
    payload_size: usize,
}

fn main() {
    // 1. Auto-select active, non-loopback network interface with assigned IPs
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
        .expect("[-] Error: No active, non-loopback network interface found.");

    eprintln!("[+] Listening on active interface: {}", interface.name);

    // 2. Open low-level raw socket datalink channel
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("[-] Error: Unhandled channel type"),
        Err(e) => panic!("[-] Error: Failed to open datalink channel: {}", e),
    };

    // 3. Setup buffered stdout writer for fast, low-latency streaming
    let stdout = io::stdout();
    let mut handle = io::BufWriter::new(stdout.lock());
    let mut packet_count = 0;
    const BATCH_FLUSH_SIZE: usize = 20; // Flush buffer every 20 captured packets

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            let mut src_port = 0;
                            let mut dst_port = 0;
                            let mut payload_sz = 0;
                            let protocol_str;

                            match ipv4.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => {
                                    protocol_str = "TCP".to_string();
                                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                        src_port = tcp.get_source();
                                        dst_port = tcp.get_destination();
                                        payload_sz = tcp.payload().len();
                                    }
                                }
                                IpNextHeaderProtocols::Udp => {
                                    protocol_str = "UDP".to_string();
                                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                        src_port = udp.get_source();
                                        dst_port = udp.get_destination();
                                        payload_sz = udp.payload().len();
                                    }
                                }
                                proto => {
                                    protocol_str = format!("{:?}", proto);
                                    payload_sz = ipv4.payload().len();
                                }
                            }

                            let timestamp = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();

                            let log = PacketLog {
                                timestamp,
                                source_mac: ethernet.get_source().to_string(),
                                dest_mac: ethernet.get_destination().to_string(),
                                source_ip: ipv4.get_source().to_string(),
                                dest_ip: ipv4.get_destination().to_string(),
                                source_port: src_port,
                                dest_port: dst_port,
                                protocol: protocol_str,
                                packet_size: packet.len(),
                                payload_size: payload_sz,
                            };

                            if let Ok(json_line) = serde_json::to_string(&log) {
                                let _ = writeln!(handle, "{}", json_line);
                                packet_count += 1;

                                if packet_count >= BATCH_FLUSH_SIZE {
                                    let _ = handle.flush();
                                    packet_count = 0;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[-] Error receiving packet: {}", e);
            }
        }
    }
}
