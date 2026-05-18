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
      ];
    };

    ruff-format = {
      enable = true;
      excludes = [
        "archived/*"
      ];
    };
  };
}
