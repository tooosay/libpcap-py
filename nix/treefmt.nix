{
  projectRootFile = "flake.nix";

  programs = {
    alejandra.enable = true;

    shfmt = {
      enable = true;

      includes = [
        "*.sh"
        "*.bash"
        "scripts/*"
      ];
      excludes = [
        "archived/*"
        "*.py"
        "*.js"
        "*.mjs"
        "*.cjs"
        "*.ts"
        "pycap_methods.inc"
      ];
    };

    clang-format = {
      enable = true;

      includes = [
        "*.c"
        "*.h"
      ];
      excludes = [
        "archived/*"
        "dist/*"
        "build/*"
        "pycap_methods.inc"
      ];
    };

    ruff-format = {
      enable = true;
      excludes = [
        "archived/*"
        "pycap_methods.inc"
      ];
    };
  };
}
