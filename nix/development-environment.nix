{ pkgs }:

let
  systemEnvironment = import ./system-environment.nix { inherit pkgs; };

  # Cargo, for reindeer and build_defs/update_buck_files.py, and
  # rust-analyzer. Buck2 downloads the same release itself. The
  # rust-overlay toolchain propagates a Nix C compiler for linking; only its
  # files are taken, so the host's compiler stays the one on PATH.
  rustToolchain = pkgs.buildEnv {
    name = "rust-toolchain";
    paths = [ (pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml) ];
    pathsToLink = [ "/bin" "/etc" "/lib" "/libexec" "/share" ];
  };

  # One Reindeer test fails on Darwin. Elsewhere the unmodified package
  # comes from the binary cache; overriding it would rebuild it from source.
  reindeer =
    if pkgs.stdenv.hostPlatform.isDarwin then
      pkgs.reindeer.overrideAttrs { doCheck = false; }
    else
      pkgs.reindeer;
in
{
  inherit systemEnvironment;

  packages = [
    rustToolchain
    reindeer
    pkgs.curl
    pkgs.dotslash
    pkgs.git
    pkgs.python3
  ] ++ pkgs.lib.optionals systemEnvironment.isLinux (
    systemEnvironment.libraries
    ++ [ pkgs.clang pkgs.pkg-config ]
  );

  env = systemEnvironment.env;

  enterShell = ''
    if [ -x "$PWD/bin/buck2" ]; then
      export PATH="$PWD/bin:$PATH"
    else
      export PATH="$DEVENV_ROOT/bin:$PATH"
    fi
    export CARGO_HOME="$(realpath -m "''${CARGO_HOME:-$HOME/.cargo}")"
  '';
}
