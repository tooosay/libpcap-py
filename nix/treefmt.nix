{
  projectRootFile = "flake.nix";

  programs.alejandra.enable = true;
  programs.ruff-format.enable = true;
  programs.clang-format.enable = true;
  programs.shfmt.enable = true;

  programs.shfmt.includes = [
    "*.sh"
    "*.bash"
    "scripts/*"
  ];
  programs.shfmt.excludes = [
    "archived/*"
    "*.py"
    "*.js"
    "*.mjs"
    "*.cjs"
    "*.ts"
  ];

  programs.clang-format.includes = [
    "*.c"
    "*.h"
  ];
  programs.clang-format.excludes = [
    "archived/*"
    "dist/*"
    "build/*"
  ];

  programs.ruff-format.excludes = [
    "archived/*"
  ];
}
