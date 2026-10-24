{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  libpcap,
  iproute2,
  # Short git revision, passed by the flake so builds between releases are distinguishable; null outside a git checkout.
  rev ? null,
}:

let
  cargoToml = lib.importTOML ./Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  version = cargoToml.package.version + lib.optionalString (rev != null) "+git.${rev}";

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
