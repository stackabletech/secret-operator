allow_k8s_contexts('gke_engineering-329019_europe-west1-d_sliebau-manni')

default_registry("docker.stackable.tech/sandbox")

custom_build(
    'docker.stackable.tech/sandbox/secret-operator',
    'nix shell -f . crate2nix -c crate2nix generate && nix-build . -A docker --argstr dockerName "${EXPECTED_REGISTRY}/secret-operator" && ./result/load-image | docker load',
    deps=['rust', 'Cargo.toml', 'Cargo.lock', 'default.nix', "nix", 'vendor'],
    ignore=['*.~undo-tree~'],
    # ignore=['result*', 'Cargo.nix', 'target', *.yaml],
    outputs_image_ref_to='result/ref',
)

# Load the latest CRDs from Nix
watch_file('result')
if os.path.exists('result'):
   k8s_yaml('result/crds.yaml')

# Exclude stale CRDs from Helm chart, and apply the rest
helm_crds, helm_non_crds = filter_yaml(
   helm(
      'deploy/helm/secret-operator',
      name='secret-operator',
      set=[
         'image.repository=docker.stackable.tech/sandbox/secret-operator',
      ],
   ),
   api_version = "^apiextensions\\.k8s\\.io/.*$",
   kind = "^CustomResourceDefinition$",
)
k8s_yaml(helm_non_crds)

# Load examples
k8s_yaml('examples/simple-consumer-nginx.yaml')
k8s_yaml('examples/simple-consumer-shell.yaml')

docker_build('docker.stackable.tech/teozkr/krb5', 'krb5')
k8s_yaml('krb5/krb5.yaml')
k8s_yaml('krb5/krb-client.yaml')
