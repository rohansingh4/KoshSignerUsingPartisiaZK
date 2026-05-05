fn main() {
    tonic_build::configure()
        .build_server(true)
        .compile(&["../proto/pqc.proto"], &["../proto"])
        .unwrap();
}
