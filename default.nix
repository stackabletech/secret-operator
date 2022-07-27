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
, dockerName ? "docker.stackable.tech/sandbox/secret-operator"
, dockerTag ? null
}:
rec {
  build = cargo.rootCrate.build;
  crds = pkgs.runCommand "secret-operator-crds.yaml" {}
  ''
    ${build}/bin/stackable-secret-operator crd > $out
  '';

  dockerImage = pkgs.dockerTools.streamLayeredImage {
    name = dockerName;
    tag = dockerTag;
    contents = [ pkgs.bashInteractive pkgs.coreutils pkgs.util-linuxMinimal ];
    config = {
      Cmd = [ (build+"/bin/stackable-secret-operator") "run" ];
    };
  };
  docker = pkgs.linkFarm "secret-operator-docker" [
    {
      name = "load-image";
      path = dockerImage;
    }
    {
      name = "ref";
      path = pkgs.writeText "${dockerImage.name}-image-tag" "${dockerImage.imageName}:${dockerImage.imageTag}";
    }
    {
      name = "crds.yaml";
      path = crds;
    }
  ];

  crate2nix = pkgs.crate2nix;
  tilt = pkgs.tilt;
}
