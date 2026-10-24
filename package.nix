{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  libpcap,
  iproute2,
}:

rustPlatform.buildRustPackage {
  pname = "netwatch-tui";
  # Keep in sync with Cargo.toml's `version` on every release — the Nix
  # derivation label otherwise drifts from the actual source contents.
  version = "0.26.1";

  src = lib.cleanSource ./.;

  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];

  buildInputs = [ libpcap ];

  # The Linux connection collector shells out to `ss`
  nativeCheckInputs = lib.optionals stdenv.hostPlatform.isLinux [ iproute2 ];

  meta = {
    description = "Real-time network diagnostics in your terminal — like htop for your network";
    homepage = "https://github.com/matthart1983/netwatch";
    license = lib.licenses.mit;
    mainProgram = "netwatch";
  };
}
