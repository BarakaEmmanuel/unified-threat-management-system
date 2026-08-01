use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure and launch virtual interface 'utm0'
    let mut config = tun::Configuration::default();
    config
        .name("utm0")
        .address((10, 8, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(false);
    });

    let mut dev = tun::create(&config)?;
    let mut buf = [0u8; 1500];

    eprintln!("[+] MTD TUN Bridge online on interface: utm0 (10.8.0.1)");
    eprintln!("[+] Intercepting outbound packets and obfuscating source IP...");

    // 2. Intercept packets moving through the bridge
    loop {
        let amount = dev.read(&mut buf)?;
        let packet = &mut buf[..amount];

        // Ensure packet is IPv4 (Version header = 4)
        if amount >= 20 && (packet[0] >> 4) == 4 {
            let src_ip = format!("{}.{}.{}.{}", packet[12], packet[13], packet[14], packet[15]);
            let dst_ip = format!("{}.{}.{}.{}", packet[16], packet[17], packet[18], packet[19]);

            // Obfuscation Layer: Rewrite source IP bytes to randomized MTD virtual IP (10.8.0.254)
            packet[12] = 10;
            packet[13] = 8;
            packet[14] = 0;
            packet[15] = 254;

            // Recalculate IPv4 header checksum to keep packet valid
            packet[10] = 0;
            packet[11] = 0;
            let checksum = compute_ip_checksum(&packet[..20]);
            packet[10] = (checksum >> 8) as u8;
            packet[11] = (checksum & 0xff) as u8;

            eprintln!(
                "[MTD Obfuscated] {} -> {} | Size: {} bytes | Target: {}",
                src_ip, "10.8.0.254", amount, dst_ip
            );
        }
    }
}

/// Simple standard Internet Checksum computation for IPv4 headers
fn compute_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = ((header[i] as u32) << 8) | (header[i + 1] as u32);
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
