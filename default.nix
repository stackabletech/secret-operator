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
      krb5-sys = attrs: {
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ (pkgs.enableDebugging pkgs.libkrb5) ];
        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.stdenv.glibc.dev}/include -I${pkgs.clang.cc.lib}/lib/clang/${pkgs.lib.getVersion pkgs.clang.cc}/include";
      };
    };
  }
, dockerTag ? "latest"
}:
rec {
  inherit pkgs;

  build = cargo.workspaceMembers.stackable-secret-operator.build;
  crds = pkgs.runCommand "secret-provisioner-crds.yaml" {}
  ''
    ${build}/bin/stackable-secret-operator crd > $out
  '';

  dockerImage = pkgs.dockerTools.streamLayeredImage {
    name = "docker.stackable.tech/teozkr/secret-provisioner";
    tag = dockerTag;
    contents = [ pkgs.bashInteractive pkgs.coreutils pkgs.util-linuxMinimal pkgs.krb5 pkgs.vim ];
    config = {
      Cmd = [
        # "${pkgs.gdb}/bin/gdbserver" ":9999"
        (build+"/bin/stackable-secret-operator") "run"
      ];
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
      name = "crds.yaml";
      path = crds;
    }
  ];

  crate2nix = pkgs.crate2nix;
  tilt = pkgs.tilt;
}
