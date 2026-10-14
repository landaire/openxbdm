{ pkgs, ... }:

{
  languages.rust = {
    enable = true;
    channel = "stable";
    # build_xbox360.sh builds `core` from source with -Zbuild-std.
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "rust-src" ];
  };

  packages = [
    pkgs.buck2
    # One of its tests fails on darwin.
    (pkgs.reindeer.overrideAttrs { doCheck = false; })
  ];
}
