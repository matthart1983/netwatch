{
  lib,
  rustPlatform,
  pkg-config,
  libpcap,
}:

rustPlatform.buildRustPackage {
  pname = "netwatch-tui";
  # Keep in sync with Cargo.toml's `version` on every release — the Nix
  # derivation label otherwise drifts from the actual source contents.
  version = "0.21.5";

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
