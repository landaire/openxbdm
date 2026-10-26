{ pkgs }:

let
  inherit (pkgs) lib;
  isLinux = pkgs.stdenv.hostPlatform.isLinux;

  libraries = lib.optionals isLinux (with pkgs; [
    alsa-lib
    fontconfig
    libxkbcommon
    udev
    vulkan-loader
    wayland
    libx11
    libxcb
  ]);

  # The packaged controller must load host GPU drivers outside Nix.
  driverPaths = lib.optionals isLinux [
    "/run/opengl-driver/lib"
    "/usr/lib64"
    "/usr/lib/x86_64-linux-gnu"
    "/usr/lib"
  ];

  libraryPath = lib.makeLibraryPath libraries;
  runtimeLibraryPath = lib.concatStringsSep ":" ([ libraryPath ] ++ driverPaths);
in
{
  inherit isLinux libraries runtimeLibraryPath;

  env = lib.optionalAttrs isLinux {
    LIBRARY_PATH = libraryPath;
    LD_LIBRARY_PATH = libraryPath;
    PKG_CONFIG_PATH = lib.makeSearchPathOutput "dev" "lib/pkgconfig" libraries;
  };
}
