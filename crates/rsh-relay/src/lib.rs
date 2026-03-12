pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/rdv.rs"));
}
pub mod codec;
pub mod relay;
pub mod rendezvous;
