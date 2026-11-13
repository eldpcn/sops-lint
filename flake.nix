{
  description = "sops-lint: a linter that understands SOPS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
    in
    {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "sops-lint";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = "${self}/Cargo.lock";
            # A flake's `self` as `src` is the tracked-files tree with
            # `.git` itself stripped (a quirk of the purified build sandbox)
            # -- and exactly one test needs a real `.git` directory present
            # to exercise config discovery from a single-file scan root.
            # Every other test either scans a directory that already
            # contains its own `.sops.yaml` fixture, or scans a file with no
            # nearby config at all either way, so skipping just this one
            # lets the rest of the suite actually run as part of `nix
            # build`. The GitHub Actions `test` job still runs the full
            # suite, `.git` included, against a normal checkout.
            checkFlags = [
              "--skip=single_file_invocation_still_finds_the_repo_wide_config"
            ];
            meta = {
              description = "A linter that understands SOPS: catches secrets that escaped encryption and files SOPS wouldn't actually cover.";
              homepage = "https://github.com/eldpcn/sops-lint";
              license = [ pkgs.lib.licenses.mit pkgs.lib.licenses.asl20 ];
              mainProgram = "sops-lint";
            };
          };
        });

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.cargo pkgs.rustc pkgs.clippy pkgs.rustfmt pkgs.rust-analyzer ];
            RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
          };
        });
    };
}
