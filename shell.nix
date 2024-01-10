let 
  pkgs = import <nixpkgs> {};
  beku = pkgs.callPackage(pkgs.fetchFromGitHub {
    owner = "stackabletech";
    repo = "beku.py";
    rev = "589e48ae45c5984d8f1528e1c0b802e9fa137715";
    hash = "sha256-hLaIY4BE+VIMeKmS3JLOZy87OC2VuQtbX/NCIbQr2p4=";
  } + "/beku.nix") {};
in pkgs.mkShell rec {
  name = "secret-operator";
  buildInputs = with pkgs; [
    # cargo et-al
    rustup

    # make regenerate charts
    yq-go
    git
    jq

    # make run-dev
    kubectl
    nix
    kubernetes-helm
    tilt
    docker
    kind

    # tests
    kuttl
    beku

    pkg-config
    clang
    libclang
    openssl
    protobuf
    krb5

    # Extra dependencies for use in a pure env (nix-shell --pure)
    # cacert
    # vim nvim nano
  ];

  LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
 }
