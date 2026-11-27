//! Library half of fips-exitd.
//!
//! The daemon itself is the binary in `src/main.rs`, which owns the sockets,
//! the TUN device and the firewall. This library holds the parts that must be
//! decidable without any of that — currently only [`admission`], the paid-exit
//! admission rule — so tests can drive them directly and so a second caller
//! (a router pushing decisions out of band) can link them instead of shelling
//! out to the Go module.
//!
//! Nothing in here performs I/O, and nothing in here is called by the daemon
//! yet: wiring it in is a separate change.

pub mod admission;
