extern crate etherparse;
extern crate tun_tap;
fn main() {
    let nic =
        tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("failed to create TUN interface");
    let mut buffer = vec![0; 1504];
    loop {
        let nbytes = nic.recv(&mut buffer).expect("unable to receive the packet");
        let tun_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
        if tun_protocol != 0x0800 {
            // not ipv4 packet
            println!("not ipv4 packet");
            continue;
        }
        match etherparse::Ipv4HeaderSlice::from_slice(&buffer[4..nbytes]) {
            Ok(packet) => {
                let source_address = packet.source_addr();
                let destination_address = packet.destination_addr();
                println!("packet from {} -> {}", source_address, destination_address);
            }
            Err(e) => {
                println!("couldn't interpret packet {:?}", e)
            }
        }
    }
}
