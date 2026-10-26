{ pkgs, ... }:

let
  # Cargo, for reindeer and build_defs/update_buck_files.py, and
  # rust-analyzer. Buck2 downloads the same release itself. The
  # rust-overlay toolchain propagates a Nix C compiler for linking; only its
  # files are taken, so the host's compiler stays the one on PATH.
  rustToolchain = pkgs.buildEnv {
    name = "rust-toolchain";
    paths = [ (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml) ];
    pathsToLink = [ "/bin" "/etc" "/lib" "/libexec" "/share" ];
  };

  # Reindeer for build_defs/update_buck_files.py. One of its tests fails on
  # darwin, so there it is built without them. Elsewhere the unmodified
  # package comes prebuilt from the binary cache; overriding it would
  # rebuild it from source.
  reindeer =
    if pkgs.stdenv.hostPlatform.isDarwin then
      pkgs.reindeer.overrideAttrs { doCheck = false; }
    else
      pkgs.reindeer;

  linuxLibraries = with pkgs; [
    alsa-lib
    fontconfig
    libxkbcommon
    udev
    vulkan-loader
    wayland
    xorg.libX11
    xorg.libxcb
  ];
in
{
  # Keep the default stdenv out of the shell. Buck2 uses Clang directly for
  # the small C shims in Linux UI dependencies.
  stdenv = pkgs.stdenvNoCC;

  packages = [
    rustToolchain
    reindeer
    pkgs.python3
  ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux (
    linuxLibraries
    ++ [ pkgs.clang pkgs.pkg-config ]
  );

  env = pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
    LIBRARY_PATH = pkgs.lib.makeLibraryPath linuxLibraries;
    LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath linuxLibraries;
    PKG_CONFIG_PATH = pkgs.lib.makeSearchPathOutput "dev" "lib/pkgconfig" linuxLibraries;
  };

  # bin/buck2 runs the Buck2 release that toolchains/buck2 pins, through the
  # DotSlash that bootstrap.sh installs, as outside the shell. DotSlash and
  # the Linux Buck2 builds are static, so they run on NixOS.
  #
  # askama, which diplomat-tool uses, writes template paths relative to the
  # source file. With CARGO_HOME under a symbolic link (/home -> var/home on
  # Fedora Atomic) the relative path walks out of the link and does not
  # resolve, so Cargo builds of openxbdm-ffi-bindgen fail.
  enterShell = ''
    export PATH="$DEVENV_ROOT/bin:$PATH"
    export CARGO_HOME="$(realpath -m "''${CARGO_HOME:-$HOME/.cargo}")"
  '';

  # bazel-remote serves the Buck2 action cache in CI.
  profiles.ci.module.packages = [ pkgs.bazel-remote ];
}
