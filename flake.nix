{
  description = "netwatch — real-time network diagnostics TUI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    # eachDefaultSystem minus x86_64-darwin, which nixpkgs dropped in 26.11:
    # listing it makes `nix flake check` fail to evaluate.
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        netwatch = pkgs.callPackage ./package.nix {
          rev = self.shortRev or self.dirtyShortRev or null;
        };
      in
      {
        packages = {
          netwatch = netwatch;
          default = netwatch;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ netwatch ];
          packages = with pkgs; [
            cargo
            rustc
            rust-analyzer
            clippy
            rustfmt
          ];
        };
      }
    );
}
