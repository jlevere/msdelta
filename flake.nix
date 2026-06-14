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
        # Nightly is only needed for cargo-fuzz (libFuzzer sanitizers); the
        # library and CLI stay on stable. Used by the `fuzz` devShell below.
        nightlyToolchain = fenix.packages.${system}.complete.toolchain;
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

            # Frida lab host/controller scripts under lab/frida.
            pkgs.nodejs_22
            pkgs.pnpm

            # Reverse engineering msdelta.dll / wcp.dll.
            # Use Ghidra's `analyzeHeadless` for scripted/repeatable analysis.
            pkgs.ghidra
            pkgs.radare2
            python
            pkgs.file
            pkgs.hexyl
          ];

          shellHook = ''
            echo "msdelta — PA30 / DCM workbench"
            echo ""
            echo "RE:     ghidra  |  radare2  |  analyzeHeadless <proj-dir> <proj-name> -import <bin>"
            echo "Build:  cargo build  |  cargo nextest run"
            echo "Lab:    pnpm --dir lab/frida run check  |  ssh jackson-dev"
            echo "Fuzz:   nix develop .#fuzz"
          '';
        };

        # Nightly toolchain + cargo-fuzz, isolated from the default stable
        # shell. Enter with `nix develop .#fuzz`.
        devShells.fuzz = pkgs.mkShell {
          name = "msdelta-fuzz";

          packages = [
            nightlyToolchain
            pkgs.cargo-fuzz
            # fuzz/coverage.sh renders reports with llvm-cov / llvm-profdata,
            # which ship in the nightly toolchain's llvm-tools component (see
            # lib/rustlib/<triple>/bin), so no extra coverage package is needed.
            pkgs.hexyl
          ];

          shellHook = ''
            echo "msdelta — fuzzing shell (nightly + cargo-fuzz)"
            echo ""
            echo "Seed:   ./fuzz/seed_corpus.sh            # real fixtures -> corpora"
            echo "List:   cargo fuzz list"
            echo "Run:    cargo fuzz run fuzz_apply -- -dict=fuzz/pa30.dict   # decoders: add -dict"
            echo "Cov:    ./fuzz/coverage.sh fuzz_apply    # what the corpus misses"
            echo "Repro:  cargo fuzz run fuzz_apply fuzz/artifacts/fuzz_apply/<crash>"
          '';
        };
      });
}
