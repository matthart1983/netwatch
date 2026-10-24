{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  libpcap,
  iproute2,
  versionCheckHook,
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

  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "--version";
  # `netwatch --version` prints the bare Cargo version, without the `+git.<rev>` suffix
  preVersionCheck = ''
    version=${cargoToml.package.version}
  '';
  # The hook accepts substring matches and ignores the command's exit status.
  # Preserve the strict smoke check that previously ran in the CI workflow.
  postVersionCheck = ''
    actualVersion=$("$out/bin/netwatch" --version) || {
      echo "netwatch --version failed" >&2
      exit 1
    }
    if [[ "$actualVersion" != "netwatch ${cargoToml.package.version}" ]]; then
      echo "Unexpected netwatch version: $actualVersion" >&2
      exit 1
    fi
  '';
  doInstallCheck = true;

  meta = {
    description = "Real-time network diagnostics in your terminal — like htop for your network";
    homepage = "https://github.com/matthart1983/netwatch";
    license = lib.licenses.mit;
    mainProgram = "netwatch";
  };
}
