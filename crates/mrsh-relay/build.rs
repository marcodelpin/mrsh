fn main() {
    prost_build::compile_protos(&["../../proto/rdv.proto"], &["../../proto/"]).unwrap();
}
