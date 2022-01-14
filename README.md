# secret-operator

Manages/generates Kubernetes secrets, and mounts them into pods using CSI

## Running

The operator must be executed inside Kubernetes, since it registers a CSI plugin against Kubelet.

Currently builds are only supported with Nix. To build and install, run:

```bash
nix run -f . crate2nix generate && nix build -f . docker && kind load image-archive <(./result/load-image) && kubectl apply -f provisioner.yaml && kubectl rollout restart ds/secret-provisioner
```

You may need to add `extra-experimental-features = nix-command` to `/etc/nix/nix.conf`, or add `--experimental-features nix-command` to the Nix commands.

You can also use [Tilt](https://tilt.dev/) to automatically recompile and redeploy when files are changed: `nix run -f . tilt up`.

## Usage

The operator injects secret data into `Pod` `Volume`s that declare a CSI volume with the `driver` `secrets.stackable.tech`.
The volume takes the following mandatory attributes:

- `secrets.stackable.tech/class`: The type of secret to be issued. This corresponds to a `SecretClass` object.
- `secrets.stackable.tech/scope`: The properties of the `Pod` that the secret should authenticate. Supported options:
  - `node`
  - `pod`
  - `secret=<foo>`
  - Multiple scopes may be defined, they should be separated by commas
  
A minimal secret-consuming `Pod` looks like this:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-secret-consumer
spec:
  volumes:
  - name: secret
    csi:
      driver: secrets.stackable.tech
      volumeAttributes:
        secrets.stackable.tech/class: tls
        secrets.stackable.tech/scope: node,pod,service=secret-consumer-nginx
  containers:
  - name: ubuntu
    image: ubuntu
    stdin: true
    tty: true
    volumeMounts:
    - name: tls
      mountPath: /tls
```

`SecretClass` defines where the secrets come from. For example, the following `SecretClass`
issues TLS certificates, storing its CA certificate in `secret-provisioner-tls-ca`:

```yaml
apiVersion: secrets.stackable.tech/v1alpha1
kind: SecretClass
metadata:
  name: tls
spec:
  backend:
    autoTls:
      ca:
        secret:
          name: secret-provisioner-tls-ca
          namespace: default
```
