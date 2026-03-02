{
  lib,
  rustPlatform,
  pkg-config,
  libpcap,
}:

rustPlatform.buildRustPackage {
  pname = "netwatch-tui";
  version = "0.3.5";

  src = lib.cleanSource ./.;

  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];

  buildInputs = [ libpcap ];

  meta = {
    description = "Real-time network diagnostics in your terminal — like htop for your network";
    homepage = "https://github.com/matthart1983/netwatch";
    license = lib.licenses.mit;
    mainProgram = "netwatch";
  };
}
