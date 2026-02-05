// Exponential backoff with jitter for reconnection
struct ExponentialBackoff {
    base: std::time::Duration,
    max: std::time::Duration,
    current: std::time::Duration,
    jitter_factor: f64,
}

impl ExponentialBackoff {
    fn new() -> Self {
        Self {
            base: std::time::Duration::from_secs(1),
            max: std::time::Duration::from_secs(60),
            current: std::time::Duration::from_secs(1),
            jitter_factor: 0.5,
        }
    }

    fn next_delay(&mut self) -> std::time::Duration {
        let delay = self.current;
        self.current = std::cmp::min(self.current * 2, self.max);
        let mut rng = rand::rng();
        let jitter = rng.random_range(-self.jitter_factor..self.jitter_factor);
        let jittered = delay.as_secs_f64() * (1.0 + jitter);
        std::time::Duration::from_secs_f64(jittered.max(0.1))
    }

    fn reset(&mut self) {
        self.current = self.base;
    }
}
