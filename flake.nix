{
  description = "libpcap-py";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs = inputs @ {
    flake-parts,
    treefmt-nix,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [
        treefmt-nix.flakeModule
      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem = {pkgs, ...}: let
        commonShellHook = ''
          if command -v starship >/dev/null 2>&1; then
            eval "$(starship init bash)"
          fi
        '';
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            python310
            libpcap
            libpcap.lib
            uv
            ninja
            meson
            pkg-config
            stdenv.cc
            just
            ruff
            clang-tools
            libclang
            deadnix
            statix
          ];

          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [pkgs.libpcap];

          UV_NO_EDITABLE = 1;
          UV_NO_CACHE = 1;
          UV_PROJECT_ENVIRONMENT = ".venv";

          shellHook = ''
            echo ${pkgs.python310.version} > .python-version
            ${commonShellHook}
          '';
        };

        treefmt = import ./nix/treefmt.nix;
      };
      flake = {
      };
    };
}
