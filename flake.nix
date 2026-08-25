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
        PY_VERSION = pkgs.python312.version;
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            libpcap
            libpcap.lib
            python312
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
            glibc
          ];

          env = {
            LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [pkgs.libpcap];
            LIBCLANG_PATH = (pkgs.lib.makeLibraryPath [pkgs.libclang]) + "/libclang.so";

            # for tools
            LIBC_INCLUDE_DIR = pkgs.glibc.dev + "/include";

            UV_NO_EDITABLE = 1;
            UV_NO_CACHE = 1;
            UV_PROJECT_ENVIRONMENT = ".venv";
            UV_PYTHON_DOWNLOADS = "never";
            UV_PYTHON = "${pkgs.python312}/bin/python3.12";
          };

          shellHook = ''
            # python312 contributes its site-packages directory to PYTHONPATH.
            # Leaving it set makes uv-managed Python 3.13+ load Python 3.12's
            # _sysconfigdata and produce extension modules with a cp312 ABI.
            unset PYTHONPATH

            version1=""
            finalVersion="${PY_VERSION}"
            if [ ! -f .python-version ]; then
               version1=$finalVersion
            else
               version1="$(cat .python-version)"
            fi
            if [  "$(printf '%s\n%s' "$version1" "${PY_VERSION}" | sort -V | head -n1)" != "${PY_VERSION}" ]; then
              echo "update PY_VERSION in flake.nix"
              finalVERSION=$version1
            fi

            echo "''${finalVersion}" > .python-version
            ${commonShellHook}
          '';
        };

        treefmt = import ./nix/treefmt.nix;
      };
      flake = {
      };
    };
}
