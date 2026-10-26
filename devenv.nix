{ pkgs, ... }:

let
  developmentEnvironment = import ./nix/development-environment.nix { inherit pkgs; };
in
{
  # Keep the default stdenv out of the shell. Buck2 uses Clang directly for
  # the small C shims in Linux UI dependencies.
  stdenv = pkgs.stdenvNoCC;

  packages = developmentEnvironment.packages;
  env = developmentEnvironment.env;
  enterShell = developmentEnvironment.enterShell;

  # bazel-remote serves the Buck2 action cache in CI.
  profiles.ci.module.packages = [ pkgs.bazel-remote ];
}
