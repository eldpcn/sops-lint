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
            # git is a runtime dep (--staged/--git-history shell out to it),
            # not just a build input -- wrapProgram makes it find it.
            nativeBuildInputs = [ pkgs.git pkgs.makeWrapper ];
            postFixup = ''
              wrapProgram $out/bin/sops-lint --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.git ]}
            '';
            # Skips the one test needing this *repo's own* .git, which the
            # flake's src (tracked files only) doesn't have. GitHub Actions
            # runs the full suite against a real checkout.
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
