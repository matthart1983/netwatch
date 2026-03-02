{
  description = "netwatch — real-time network diagnostics TUI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        netwatch = pkgs.callPackage ./package.nix { };
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
