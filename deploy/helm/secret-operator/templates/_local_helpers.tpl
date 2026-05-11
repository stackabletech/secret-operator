{{/*
Expand the image name for csi-provisioner
*/}}
{{- define "csi-provisioner.image" -}}
{{- printf "%s/csi-provisioner:%s" (.Values.csiNodeDriver.externalProvisioner.image.repository | default (printf "%s/sig-storage" .Values.image.repository)) .Values.csiNodeDriver.externalProvisioner.image.tag }}
{{- end }}

{{/*
Expand the image name for csi-node-driver-registrar
*/}}
{{- define "csi-node-driver-registrar.image" -}}
{{- printf "%s/csi-node-driver-registrar:%s" (.Values.csiNodeDriver.nodeDriverRegistrar.image.repository | default (printf "%s/sig-storage" .Values.image.repository)) .Values.csiNodeDriver.nodeDriverRegistrar.image.tag }}
{{- end }}
