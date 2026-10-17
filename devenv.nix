{ pkgs, lib, ... }:

let
  # Buck2 comes from its own release: the test rules need 2026-10-01 or
  # later, which nixpkgs may not have yet. The musl builds are static. CI on
  # Windows installs the same release from the same file.
  buck2Release = lib.importJSON ./toolchains/buck2_release.json;
  system = pkgs.stdenv.hostPlatform.system;
  buck2Asset =
    buck2Release.assets.${system}
      or (throw "toolchains/buck2_release.json pins no Buck2 asset for ${system}");

  buck2 = pkgs.stdenvNoCC.mkDerivation {
    pname = "buck2";
    version = buck2Release.tag;
    src = pkgs.fetchurl {
      url = "https://github.com/facebook/buck2/releases/download/${buck2Release.tag}/${buck2Asset.asset}";
      inherit (buck2Asset) sha256;
    };
    nativeBuildInputs = [ pkgs.zstd ];
    dontUnpack = true;
    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin
      zstd -d "$src" -o $out/bin/buck2
      chmod +x $out/bin/buck2
      runHook postInstall
    '';
    meta.mainProgram = "buck2";
  };

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
in
{
  # Buck2 links with the host's C compiler driver (cc, c++ and ar on Linux,
  # Xcode's clang on macOS), so the shell provides none: the binaries then
  # depend on the host's C library rather than on Nix store paths.
  stdenv = pkgs.stdenvNoCC;

  packages = [
    buck2
    rustToolchain
    reindeer
    pkgs.python3
  ];

  # askama, which diplomat-tool uses, writes template paths relative to the
  # source file. With CARGO_HOME under a symbolic link (/home -> var/home on
  # Fedora Atomic) the relative path walks out of the link and does not
  # resolve, so Cargo builds of openxbdm-ffi-bindgen fail.
  enterShell = ''
    export CARGO_HOME="$(realpath -m "''${CARGO_HOME:-$HOME/.cargo}")"
  '';

  # bazel-remote serves the Buck2 action cache in CI.
  profiles.ci.module.packages = [ pkgs.bazel-remote ];
}
