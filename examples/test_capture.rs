fn main() {
    println!("Listing devices...");
    match pcap::Device::list() {
        Ok(devices) => {
            for d in &devices {
                println!("  {} - {:?}", d.name, d.desc);
            }
            if let Some(dev) = devices.first() {
                println!("\nTrying to capture on {}...", dev.name);
                match pcap::Capture::from_device(dev.name.as_str()) {
                    Ok(cap) => {
                        println!("  Created inactive capture OK");
                        match cap.promisc(false).snaplen(256).timeout(1000).open() {
                            Ok(mut active) => {
                                println!("  Opened capture OK, waiting for packet...");
                                match active.next_packet() {
                                    Ok(pkt) => println!("  Got packet: {} bytes", pkt.data.len()),
                                    Err(e) => println!("  Next packet error: {}", e),
                                }
                            }
                            Err(e) => println!("  Open failed: {}", e),
                        }
                    }
                    Err(e) => println!("  from_device failed: {}", e),
                }
            }
        }
        Err(e) => eprintln!("Error listing devices: {}", e),
    }
}
