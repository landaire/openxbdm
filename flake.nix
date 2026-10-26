{
  description = "openxbdm host tools and development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, rust-overlay, ... }:
    let
      workspaceManifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      workspaceVersion = workspaceManifest.workspace.package.version;

      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          inherit (pkgs) lib;
          systemEnvironment = import ./nix/system-environment.nix { inherit pkgs; };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
          cargoPackages = [
            "openxbdm-cli"
            "openxbdm-ffi-bindgen"
            "openxbdm-kd"
            "openxbdm-server-host"
            "xeedee-controller"
          ];
          cargoPackageFlags = lib.concatMap (name: [ "--package=${name}" ]) cargoPackages;
          openxbdmTools = rustPlatform.buildRustPackage {
            pname = "openxbdm-tools";
            version = workspaceVersion;

            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./Cargo.lock
                ./Cargo.toml
                ./README.md
                ./openxbdm
                ./third-party/rust/Cargo.toml
                ./third-party/rust/lib.rs
              ];
            };
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = cargoPackageFlags;
            cargoTestFlags = cargoPackageFlags;

            nativeBuildInputs = lib.optionals systemEnvironment.isLinux [
              pkgs.makeWrapper
              pkgs.pkg-config
            ];
            buildInputs = systemEnvironment.libraries;

            postInstall = lib.optionalString systemEnvironment.isLinux ''
              wrapProgram "$out/bin/xeedee-controller" \
                --prefix LD_LIBRARY_PATH : "${systemEnvironment.runtimeLibraryPath}"
            '';

            meta = {
              description = "Host tools for Xbox 360 development consoles";
              homepage = "https://github.com/landaire/xeedee";
              license = with lib.licenses; [
                asl20
                mit
              ];
              platforms = systems;
            };
          };
          singleTool =
            name: description:
            pkgs.runCommand name
              {
                meta = openxbdmTools.meta // {
                  inherit description;
                  mainProgram = name;
                };
              }
              ''
                mkdir -p "$out/bin"
                ln -s "${openxbdmTools}/bin/${name}" "$out/bin/${name}"
              '';
        in
        rec {
          openxbdm-tools = openxbdmTools;
          openxbdm-ffi-bindgen = singleTool "openxbdm-ffi-bindgen" "Generate C++ headers for openxbdm-ffi";
          openxbdm-kd = singleTool "openxbdm-kd" "Use the Xbox 360 kernel debugger transport and GDB bridge";
          openxbdm-server = singleTool "openxbdm-server" "Run the host-backed openxbdm server";
          xeedee = singleTool "xeedee" "Control an Xbox 360 development console over XBDM";
          xeedee-controller = singleTool "xeedee-controller" "Relay controller input to an Xbox 360 development console";
          default = openxbdm-tools;
        }
      );

      apps = forAllSystems (
        system:
        let
          packages = self.packages.${system};
          app = name: {
            type = "app";
            program = "${packages.${name}}/bin/${name}";
          };
        in
        {
          openxbdm-ffi-bindgen = app "openxbdm-ffi-bindgen";
          openxbdm-kd = app "openxbdm-kd";
          openxbdm-server = app "openxbdm-server";
          xeedee = app "xeedee";
          xeedee-controller = app "xeedee-controller";
          default = app "xeedee";
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          developmentEnvironment = import ./nix/development-environment.nix { inherit pkgs; };
        in
        {
          default = pkgs.mkShellNoCC (
            developmentEnvironment.env
            // {
              packages = developmentEnvironment.packages;
              shellHook = developmentEnvironment.enterShell;
            }
          );
        }
      );
    };
}
