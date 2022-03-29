allow_k8s_contexts('gke_engineering-329019_europe-west1-b_teo')

custom_build(
    'docker.stackable.tech/teozkr/secret-provisioner',
    'nix run -f . crate2nix generate && nix-build . -A docker --arg dockerTag null && ./result/load-image | docker load',
    deps=['rust', 'Cargo.toml', 'Cargo.lock', 'default.nix', 'vendor'],
    ignore=['*.~undo-tree~'],
    # ignore=['result*', 'Cargo.nix', 'target', *.yaml],
    outputs_image_ref_to='result/ref',
)
k8s_yaml('provisioner.yaml')
k8s_yaml('examples/simple-consumer-nginx.yaml')
watch_file('result')
if os.path.exists('result'):
   k8s_yaml('result/crds.yaml')

docker_build('docker.stackable.tech/teozkr/krb5', 'krb5')
k8s_yaml('krb5/krb5.yaml')
k8s_yaml('krb5/krb-client.yaml')