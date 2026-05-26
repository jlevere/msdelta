{
  description = "Pure-Rust encoder and decoder for Microsoft's MSDelta (PA30) binary patch format";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
        toolchain = fenix.packages.${system}.stable.toolchain;
        python = pkgs.python313.withPackages (ps: [
          ps.pefile     # PE structure parsing for msdelta.dll / wcp.dll
          ps.capstone   # disassembly snippets when scripting analysis
        ]);
      in {
        devShells.default = pkgs.mkShell {
          name = "msdelta";

          packages = [
            toolchain
            pkgs.rust-analyzer
            pkgs.cargo-nextest
            pkgs.cargo-expand

            # Reverse engineering msdelta.dll / wcp.dll.
            # Use Ghidra's `analyzeHeadless` for scripted/repeatable analysis.
            pkgs.ghidra
            python
            pkgs.file
            pkgs.hexyl
          ];

          shellHook = ''
            echo "msdelta — PA30 / DCM workbench"
            echo ""
            echo "RE:     ghidra  |  analyzeHeadless <proj-dir> <proj-name> -import <bin>"
            echo "Build:  cargo build  |  cargo nextest run"
          '';
        };
      });
}
