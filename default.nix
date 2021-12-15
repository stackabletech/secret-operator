{ nixpkgs ? <nixpkgs>
, pkgs ? import nixpkgs {}
, cargo ? import ./Cargo.nix {
    inherit nixpkgs pkgs; release = false;
    defaultCrateOverrides = pkgs.defaultCrateOverrides // {
      prost-build = attrs: {
        buildInputs = [ pkgs.protobuf ];
      };
      tonic-reflection = attrs: {
        buildInputs = [ pkgs.rustfmt ];
      };
      stackable-secret-operator = attrs: {
        buildInputs = [ pkgs.rustfmt ];
      };
    };
  }
}:
rec {
  build = cargo.rootCrate.build;
  crate2nix = pkgs.crate2nix;
  docker = pkgs.dockerTools.streamLayeredImage {
    name = "secret-provisioner";
    tag = "latest";
    config = {
      Cmd = [ (build+"/bin/stackable-secret-operator") ];
    };
  };
}
