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
      krb5-sys = attrs: {
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ (pkgs.enableDebugging pkgs.krb5) ];
        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.glibc.dev}/include -I${pkgs.clang.cc.lib}/lib/clang/${pkgs.lib.getVersion pkgs.clang.cc}/include";
      };
    };
  }
, dockerName ? "docker.stackable.tech/sandbox/secret-operator"
, dockerTag ? null
}:
rec {
  inherit pkgs;

  build = cargo.workspaceMembers.stackable-secret-operator.build;
  crds = pkgs.runCommand "secret-operator-crds.yaml" {}
  ''
    ${build}/bin/stackable-secret-operator crd > $out
  '';

  dockerImage = pkgs.dockerTools.streamLayeredImage {
    name = dockerName;
    tag = dockerTag;
    contents = [ pkgs.bashInteractive pkgs.coreutils pkgs.util-linuxMinimal pkgs.krb5 pkgs.vim cargo.workspaceMembers.stackable-krb5-provision-keytab.build ];
    config = {
      Cmd = [
        # "${pkgs.gdb}/bin/gdbserver" ":9999"
        (build+"/bin/stackable-secret-operator") "run"
      ];
      # Env = [
      #   "KRB5_TRACE=/dev/stderr"
      # ];
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
