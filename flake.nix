{
  description = "libpcap-py";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        let
          commonShellHook = ''
            if command -v starship >/dev/null 2>&1; then
              eval "$(starship init bash)"
            fi
          '';
        in
        {
          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              python310
              libpcap
              libpcap.lib
              uv
              ninja
              pkg-config
              stdenv.cc
            ];

            LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.libpcap ];

            shellHook = ''
              ${commonShellHook}
            '';
          };
        };
      flake = {
      };
    };
}
