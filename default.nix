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
  dockerImage = pkgs.dockerTools.streamLayeredImage {
    name = "docker.stackable.tech/teozkr/secret-provisioner";
    config = {
      Cmd = [ (build+"/bin/stackable-secret-operator") ];
    };
  };
  docker = pkgs.linkFarm "secret-provisioner-docker" [
    {
      name = "load-image";
      path = dockerImage;
    }
    {
      name = "ref";
      path = pkgs.writeText "${dockerImage.name}-image-tag" "${dockerImage.imageName}:${dockerImage.imageTag}";
    }
  ];
}
