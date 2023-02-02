{ sources ? import ./nix/sources.nix # managed by https://github.com/nmattia/niv
, nixpkgs ? sources.nixpkgs
, pkgs ? import nixpkgs {}
, cargo ? import ./Cargo.nix {
    inherit nixpkgs pkgs; release = false;
    defaultCrateOverrides = pkgs.defaultCrateOverrides // {
      tonic-reflection = attrs: {
        buildInputs = [ pkgs.protobuf pkgs.rustfmt ];
      };
      stackable-secret-operator = attrs: {
        buildInputs = [ pkgs.protobuf pkgs.rustfmt ];
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
      name = "image-repo";
      path = pkgs.writeText "${dockerImage.name}-repo" dockerImage.imageName;
    }
    {
      name = "image-tag";
      path = pkgs.writeText "${dockerImage.name}-tag" dockerImage.imageTag;
    }
    {
      name = "crds.yaml";
      path = crds;
    }
  ];

  # need to use vendored crate2nix because of https://github.com/kolloch/crate2nix/issues/264
  crate2nix = pkgs.callPackage sources.crate2nix {};
  tilt = pkgs.tilt;
}
