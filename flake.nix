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
            # The test suite relies on a real `.git` directory (config
            # discovery walks up looking for one), but a flake's `self` as
            # `src` is the tracked-files tree with `.git` itself stripped --
            # that's a quirk of the purified build sandbox, not something
            # any real invocation of this tool ever hits (a pre-commit hook,
            # a human, or CI always runs it against a live git checkout).
            # The GitHub Actions `test` job runs the full suite against a
            # normal checkout instead; this is just the package build.
            doCheck = false;
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
