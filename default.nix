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
, dockerTag ? "latest"
}:
rec {
  build = cargo.rootCrate.build;
  dockerImage = pkgs.dockerTools.streamLayeredImage {
    name = "docker.stackable.tech/teozkr/secret-provisioner";
    tag = dockerTag;
    config = {
      Cmd = [ (build+"/bin/stackable-secret-operator") "run" ];
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
    {
      name = "crd.yaml";
      path = pkgs.runCommand "secret-provisioner-crd.yaml" {
        # FIXME: CSI endpoint is currently always required...
        CSI_ENDPOINT = "foo";
      }
      ''
        ${build}/bin/stackable-secret-operator crd > $out
      '';
    }
  ];

  crate2nix = pkgs.crate2nix;
  tilt = pkgs.tilt;
}
