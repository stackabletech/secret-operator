custom_build(
    'docker.stackable.tech/teozkr/secret-provisioner',
    'nix run -f . crate2nix generate && nix-build . -A docker --arg dockerTag null && ./result/load-image | docker load',
    deps=['src', 'Cargo.toml', 'Cargo.lock', 'default.nix', 'build.rs', 'vendor'],
    # ignore=['result*', 'Cargo.nix', 'target', *.yaml],
    outputs_image_ref_to='result/ref',
)
k8s_yaml('provisioner.yaml')
k8s_yaml('example-consumer-nginx.yaml')
watch_file('result')
if os.path.exists('result'):
   k8s_yaml('result/crds.yaml')
