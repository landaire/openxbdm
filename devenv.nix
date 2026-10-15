{ pkgs, ... }:

{
  # The release that rustup and Buck2 use; see rust-toolchain.toml.
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = [
    pkgs.buck2
    # One of its tests fails on darwin.
    (pkgs.reindeer.overrideAttrs { doCheck = false; })
    # llvm-mc and llvm-objdump for build_xbox360.sh.
    pkgs.llvmPackages.llvm
  ];
}
