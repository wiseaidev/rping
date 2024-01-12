use std::io;
use std::io::Write;
use std::time::Instant;

/// Represents a custom progress bar for displaying flooding progress.
///
/// This progress bar includes styling with green coloring and additional information such as remaining time.
pub struct ProgressBar {
    /// The total number of iterations (e.g., total packets to be sent).
    total: usize,
    /// The total duration of the flooding process in seconds.
    duration: usize,
    /// The time when the progress bar started.
    start_time: Instant,
}

impl ProgressBar {
    /// Creates a new instance of `ProgressBar`.
    ///
    /// # Arguments
    ///
    /// * `total` - The total number of iterations.
    /// * `duration` - The total duration of the flooding process in seconds.
    ///
    /// # Returns
    ///
    /// A new `ProgressBar` instance.
    pub fn new(total: usize, duration: usize) -> Self {
        ProgressBar {
            total,
            duration,
            start_time: Instant::now(),
        }
    }

    /// Increments the progress bar and displays flooding progress information.
    ///
    /// # Arguments
    ///
    /// * `value` - The current value representing progress (e.g., packets sent).
    ///
    /// # Example
    ///
    /// ```
    /// use rping::progress_bar::ProgressBar;
    ///
    /// let mut progress_bar = ProgressBar::new(100, 10);
    /// progress_bar.inc(25);
    /// ```
    pub fn inc(&mut self, value: usize) {
        // Calculate progress percentage
        let progress_percentage = (value as f64 / self.total as f64) * 100.0;

        // Calculate remaining time
        let elapsed_time = self.start_time.elapsed().as_secs() as usize;
        let remaining_time = if elapsed_time > 0 {
            self.duration - elapsed_time
        } else {
            0
        };

        let progress_bar = format!(
            "\x1B[32m{}>\x1B[0m",
            "=".repeat((progress_percentage / 2.0).floor() as usize),
        );

        // Print progress bar and information
        if remaining_time < 60 {
            println!(
                "\x1B[2J\x1B[HFlooding in Progress: [{:<60}] {:.2}% | Remaining Time: {}s",
                progress_bar, progress_percentage, remaining_time
            );
        } else {
            println!(
                "\x1B[2J\x1B[HFlooding in Progress: [{:<60}>] {:.2}% | Remaining Time: {}min",
                progress_bar,
                progress_percentage,
                remaining_time / 60
            );
        }

        io::stdout().flush().unwrap();
    }
}
