# Building the Operator

This operator is written in Rust.

It is developed against the latest stable Rust release, and we currently don't support any older versions.

However, the Secret Operator is a [Container Storage Interface (CSI)](https://github.com/container-storage-interface/spec/blob/master/spec.md) provider plugin
for the local Kubelet, which means that it should only be executed inside of a Kubernetes `Pod`. We currently support two ways of building the
Secret Operator: `docker build` and [Nix](https://nixos.org/). `docker build` is currently our primary deployment target, and our official images are built
using it. However, Nix has much faster incremental build and deploy times, making it ideal for local development.

## Docker

To build and deploy to the active Kind cluster, run:

```shell
$ echo Building with Docker
# Ensure that all submodules are up-to-date
$ git submodule update --recursive --init
# Create a unique image ID
$ REPO=secret-operator
$ TAG="$(uuidgen)"
# Build the image
$ docker build . -f docker/Dockerfile -t "$REPO:$TAG"
# Load the image onto the Kind nodes
$ kind load docker-image "$REPO:$TAG"
# Deploy latest CRD
$ docker run --rm "$REPO:$TAG" crd | kubectl apply -f-
# Deploy
$ helm upgrade secret-operator deploy/helm/secret-operator \
       --install \
       --set-string "image.repository=$REPO,image.tag=$TAG"
```

## Nix

To build and deploy to the active Kind cluster, run the following Bash commands:

```shell
$ echo Building with Nix
# Ensure that all submodules are up-to-date
$ git submodule update --recursive --init
# Use crate2nix (https://github.com/kolloch/crate2nix) to convert Cargo.lock into a Nix derivation
$ nix run -f . crate2nix generate
# Build the Docker images
# A custom Docker repository can be specified by appending `--argstr dockerName my-custom-registry/secret-operator`
$ nix build -f . docker
# Load the images onto the Kind nodes
# Nix does not use the Docker daemon, instead it builds individual layers, as well as
# a script (`result/load-image`) that combines them into a Docker image archive.
# `load-image` can also be piped into `docker load` to prepare for pushing to a registry.
$ ./result/load-image > image.tar && kind load image-archive image.tar
# On single-node kind clusters it is slightly more efficient to run
# `./result/load-image | kind load image-archive /dev/stdin` instead.
# Deploy
$ kubectl apply -f result/crds.yaml
$ helm upgrade secret-operator deploy/helm/secret-operator \
  --install \
  --set-string "image.repository=$(cat result/image-repo),image.tag=$(cat result/image-tag)"
```

You may need to add `extra-experimental-features = nix-command` to `/etc/nix/nix.conf`, or add `--experimental-features nix-command` to the Nix commands.

You can also use [Tilt](https://tilt.dev/) to automatically rebuild and redeploy when files are changed:

```shell
$ nix run -f . tilt up
```

## K3d

Secret-Operator, as with most CSI providers, requires the Kubernetes node's root folder to be mounted as `rshared`. K3d does not do this by default,
but can be prodded into doing this by running `mount --make-rshared /` in each node container.

To do this for each running node K3d node, run the following script:

```shell
for i in $(k3d node list -o json | jq -r .[].name); do
  docker exec -it $i mount --make-rshared /
done
```

> [!IMPORTANT]
> This is _not_ persistent, and must be re-executed every time the cluster (or a node in it) is restarted.

## Local builds

Local builds (outside of the tools mentioned above) require the openssl, krb5, and Clang libraries, as well as
pkg-config and protoc. On Ubuntu, this means running:

```shell
$ sudo apt install libssl-dev libkrb5-dev libclang-dev pkg-config protobuf-compiler
```
