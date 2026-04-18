pub mod app;
pub mod collectors;
pub mod config;
pub mod ebpf;
pub mod event;
pub mod platform;
pub mod remote;
pub mod theme;
pub mod ui;

/// A simple hello world function that returns a greeting message.
pub fn hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world() {
        assert_eq!(hello_world(), "Hello, World!");
    }
}
