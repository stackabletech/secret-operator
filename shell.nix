let
  # sources = import ./nix/sources.nix;
  # pkgs = import sources.nixpkgs {};

  self = import ./. {};
  inherit (self) sources pkgs;


  beku = pkgs.callPackage (sources."beku.py" + "/beku.nix") {};



  cargoDependencySetOfCrate = crate: [ crate ] ++ pkgs.lib.concatMap cargoDependencySetOfCrate (crate.dependencies ++ crate.buildDependencies);
  cargoDependencySet = pkgs.lib.unique (pkgs.lib.flatten (pkgs.lib.mapAttrsToList (crateName: crate: cargoDependencySetOfCrate crate.build) self.cargo.workspaceMembers));
in pkgs.mkShell rec {
  name = "secret-operator";

  # want to test:
  # cargo clippy --all-targets
  # cargo test
  # cargo doc --document-private-items
  # make regenerate-charts
  # make run-dev
  # ./scripts/run_tests.sh

  packages = with pkgs; [
    ## cargo et-al
    rustup # this breaks pkg-config if it is in the nativeBuildInputs

    # Extra dependencies for use in a pure env (nix-shell --pure)
    # cacert
    # vim nvim nano
  ];

  # derivation runtime dependencies
  buildInputs = pkgs.lib.concatMap (crate: crate.buildInputs) cargoDependencySet ++ [ pkgs.libz ];
  # build time dependencies
  nativeBuildInputs = pkgs.lib.concatMap (crate: crate.nativeBuildInputs) cargoDependencySet ++ (with pkgs; [
    pkg-config
    clang 
    openssl
    protobuf
    krb5 

    git
    yq-go
    jq
    kubectl
    nix
    kubernetes-helm
    # tilt already defined in default.nix
    docker
    kind

    kuttl
    beku
    which
    gettext # for the proper envsubst
  ]);

  LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
}
