let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs {};
  beku = pkgs.callPackage (sources."beku.py" + "/beku.nix") {};
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

    # specific to this operator
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
