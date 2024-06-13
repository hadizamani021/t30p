extern crate etherparse;
extern crate tun_tap;
mod tcp_packet;

fn main() {
    let nic =
        tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("failed to create TUN interface");
    let mut buffer = [0; 1504];
    loop {
        let nbytes = nic.recv(&mut buffer).expect("unable to receive the packet");
        match tcp_packet::TCPPacket::new(&buffer[..nbytes]) {
            Ok(packet) => {
                println!(
                    "packet from {}:{} -> {}:{}",
                    packet.source_address(),
                    packet.source_port(),
                    packet.destination_address(),
                    packet.destination_port()
                );
            }
            Err(error) => {
                println!("{}", error.message)
            }
        }
    }
}
