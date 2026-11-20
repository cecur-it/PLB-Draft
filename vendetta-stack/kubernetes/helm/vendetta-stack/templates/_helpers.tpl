{{/*
Traces: PROMPT section 1 Tier 3; CONTRACT sections 2 (names, PKI file names), 8, 11.
Service names are the compose service names (the shipped configs address them literally), so nothing is prefixed.
*/}}

{{- define "vs.image" -}}
{{- $reg := trimSuffix "/" .root.Values.global.imageRegistry -}}
{{- $prefix := ternary (printf "%s/" $reg) "" (ne $reg "") -}}
{{- $tag := default .root.Values.global.stackVersion .img.tag -}}
{{- if .img.digest -}}
{{- printf "%s%s:%s@%s" $prefix .img.repository $tag .img.digest -}}
{{- else -}}
{{- printf "%s%s:%s" $prefix .img.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "vs.selector" -}}
app.kubernetes.io/name: vendetta-stack
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "vs.labels" -}}
{{ include "vs.selector" . }}
app.kubernetes.io/part-of: vendetta-stack
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "vs.peer" -}}
- podSelector:
    matchLabels:
      app.kubernetes.io/name: vendetta-stack
      app.kubernetes.io/instance: {{ .root.Release.Name }}
      app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "vs.podDefaults" -}}
serviceAccountName: vendetta-stack
automountServiceAccountToken: false
enableServiceLinks: false
{{- with .root.Values.global.imagePullSecrets }}
imagePullSecrets:
{{ toYaml . | indent 2 }}
{{- end }}
{{- end -}}

{{- define "vs.podSecurity" -}}
runAsNonRoot: true
runAsUser: {{ .uid }}
runAsGroup: {{ default .uid .gid }}
fsGroup: {{ default .uid .fsGroup }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "vs.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: {{ if and (hasKey . "readOnly") (not .readOnly) }}false{{ else }}true{{ end }}
capabilities:
  drop: ["ALL"]
  {{- with .add }}
  add: {{ toJson . }}
  {{- end }}
{{- end -}}

{{- define "vs.scheduling" -}}
{{- $cfg := default (dict) .cfg -}}
{{- $coTarget := ternary "errow" "vendetta-manager" .root.Values.errow.enabled -}}
{{- $co := and .co (ne .root.Values.global.sharedAccessMode "ReadWriteMany") (ne .component $coTarget) -}}
{{- with $cfg.nodeSelector }}
nodeSelector:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with $cfg.tolerations }}
tolerations:
{{ toYaml . | indent 2 }}
{{- end }}
{{- if $cfg.affinity }}
affinity:
{{ toYaml $cfg.affinity | indent 2 }}
{{- else if or $co .spread }}
affinity:
{{- if $co }}
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - topologyKey: kubernetes.io/hostname
        labelSelector:
          matchLabels:
{{ include "vs.selector" (dict "root" .root "component" $coTarget) | indent 12 }}
{{- end }}
{{- if .spread }}
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels:
{{ include "vs.selector" (dict "root" .root "component" .component) | indent 14 }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "vs.storageClass" -}}
{{- if .shared -}}
{{- default .root.Values.global.sharedStorageClass .class -}}
{{- else -}}
{{- default .root.Values.global.storageClass .class -}}
{{- end -}}
{{- end -}}

{{- define "vs.vct" -}}
- metadata:
    name: {{ default "data" .name }}
    labels:
{{ include "vs.labels" (dict "root" .root "component" .component) | indent 6 }}
  spec:
    accessModes: [ReadWriteOnce]
    {{- with (include "vs.storageClass" (dict "root" .root "class" .class)) }}
    storageClassName: {{ . | quote }}
    {{- end }}
    resources:
      requests:
        storage: {{ .size }}
{{- end -}}

{{- define "vs.pvc" -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ .name }}
  labels:
{{ include "vs.labels" (dict "root" .root "component" .component) | indent 4 }}
spec:
  accessModes: [{{ if .shared }}{{ .root.Values.global.sharedAccessMode }}{{ else }}ReadWriteOnce{{ end }}]
  {{- with (include "vs.storageClass" (dict "root" .root "class" .class "shared" .shared)) }}
  storageClassName: {{ . | quote }}
  {{- end }}
  resources:
    requests:
      storage: {{ .size }}
{{- end -}}

{{- define "vs.tree" -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .name }}
  labels:
{{ include "vs.labels" (dict "root" .root "component" .component) | indent 4 }}
data:
{{- $prefix := printf "files/%s/" .dir }}
{{- range $path, $_ := .root.Files.Glob (printf "files/%s/**" .dir) }}
  {{ trimPrefix $prefix $path | replace "/" "__" | quote }}: {{ $.root.Files.Get $path | toJson }}
{{- end }}
{{- end -}}

{{- define "vs.treeItems" -}}
{{- $prefix := printf "files/%s/" .dir -}}
{{- range $path, $_ := .root.Files.Glob (printf "files/%s/**" .dir) }}
- key: {{ trimPrefix $prefix $path | replace "/" "__" | quote }}
  path: {{ trimPrefix $prefix $path | quote }}
{{- end }}
{{- end -}}

{{- define "vs.secretsVolume" -}}
- name: secrets
  secret:
    secretName: {{ .root.Values.secrets.existingSecret }}
    defaultMode: 0440
    items:
{{- range .names }}
      - key: {{ . }}
        path: {{ . }}
{{- end }}
{{- end -}}

{{- define "vs.pkiVolume" -}}
{{- $root := .root -}}
{{- $cm := $root.Values.certManager.enabled -}}
- name: {{ default "pki" .volume }}
  projected:
    defaultMode: 0440
    sources:
{{- if ne (default "ca.crt" .caPath) "-" }}
      - secret:
          name: {{ ternary "vendetta-ca-root" $root.Values.pki.existingSecret $cm }}
          items:
            - key: {{ ternary "tls.crt" "ca.crt" $cm }}
              path: {{ default "ca.crt" .caPath }}
{{- end }}
{{- range .certs }}
      - secret:
          name: {{ ternary (printf "%s-tls" .svc) $root.Values.pki.existingSecret $cm }}
          items:
            - key: {{ ternary "tls.crt" (printf "%s.crt" .svc) $cm }}
              path: {{ default (printf "%s.crt" .svc) .crt }}
            - key: {{ ternary "tls.key" (printf "%s.key" .svc) $cm }}
              path: {{ default (printf "%s.key" .svc) .key }}
{{- end }}
{{- end -}}

{{- define "vs.pemInit" -}}
- name: pki-pem
  image: {{ include "vs.image" (dict "root" .root "img" .root.Values.images.busybox) }}
  imagePullPolicy: {{ .root.Values.global.imagePullPolicy }}
  command:
    - /bin/sh
    - -ec
    - umask 027; cat /pki-src/{{ .svc }}.crt /pki-src/{{ .svc }}.key > /pki/{{ .svc }}.pem; cp /pki-src/ca.crt /pki/ca.crt
  securityContext:
{{ include "vs.containerSecurity" (dict) | indent 4 }}
  resources:
    requests: {cpu: 10m, memory: 8Mi}
    limits: {cpu: 100m, memory: 16Mi}
  volumeMounts:
    - {name: {{ .src }}, mountPath: /pki-src, readOnly: true}
    - {name: {{ .dst }}, mountPath: /pki}
{{- end -}}

{{- define "vs.profileEnv" -}}
- name: CS3_PROFILE
  valueFrom:
    configMapKeyRef:
      name: vendetta-stack-profile
      key: CS3_PROFILE
{{- end -}}

{{- define "vs.certDns" -}}
{{- $ns := .root.Release.Namespace -}}
{{- $names := list .svc "localhost" (printf "%s.%s" .svc $ns) (printf "%s.%s.svc" .svc $ns) (printf "%s.%s.svc.cluster.local" .svc $ns) -}}
{{- range .extra }}{{ $names = append $names . }}{{ end -}}
{{- toYaml $names -}}
{{- end -}}

{{- define "vs.egressExternal" -}}
{{- if ne .root.Values.global.profile "airgap" }}
  {{- range .rules }}
- to:
    - ipBlock:
        cidr: {{ .cidr }}
        {{- with .except }}
        except:
{{ toYaml . | indent 10 }}
        {{- end }}
  {{- with .ports }}
  ports:
    {{- range . }}
    - protocol: {{ default "TCP" .protocol }}
      port: {{ .port }}
    {{- end }}
  {{- end }}
  {{- end }}
{{- end }}
{{- end -}}

{{- define "vs.validate" -}}
{{- if and (eq .Values.global.profile "airgap") (or .Values.config.errowCloudEnabled .Values.fluentBit.legs.console.enabled .Values.fluentBit.legs.esoc.enabled .Values.fluentBit.legs.siem.enabled) -}}
{{- fail "global.profile=airgap forbids external legs: disable config.errowCloudEnabled and fluentBit.legs.*" -}}
{{- end -}}
{{- if not (has .Values.ollama.mode (list "gpu" "cpu" "mock" "none")) -}}
{{- fail "ollama.mode must be one of gpu, cpu, mock, none" -}}
{{- end -}}
{{- if not (has .Values.fluentBit.variant (list "distroless" "debug")) -}}
{{- fail "fluentBit.variant must be distroless or debug" -}}
{{- end -}}
{{- if and .Values.errow.viewer.ingress.enabled (not .Values.errow.viewer.ingress.basicAuthSecret) -}}
{{- fail "errow.viewer.ingress.basicAuthSecret is required: the viewer has no authentication of its own" -}}
{{- end -}}
{{- if and (ne (int .Values.opensearch.replicas) 1) (lt (int .Values.opensearch.replicas) 3) -}}
{{- fail "opensearch.replicas must be 1 (single-node) or at least 3 (quorum)" -}}
{{- end -}}
{{- end -}}

{{- define "vs.env" -}}
{{- range $k, $v := . }}
- name: {{ $k }}
  value: {{ $v | toString | quote }}
{{- end }}
{{- end -}}

{{- define "vs.osHealthCmd" -}}
{{- list "/bin/sh" "-c" "curl -fsS --cacert /usr/share/opensearch/config/certs/ca.crt -u \"admin:$(cat /run/secrets/opensearch_admin_password)\" 'https://localhost:9200/_cluster/health?local=true' >/dev/null" | toJson -}}
{{- end -}}

{{- define "vs.dashboardsHealthCmd" -}}
{{- list "/bin/sh" "-c" "curl -fsS -u \"admin:$(cat /run/secrets/opensearch_admin_password)\" http://localhost:5601/api/status >/dev/null" | toJson -}}
{{- end -}}

{{- define "vs.wgetCmd" -}}
{{- list "wget" "-q" "-O" "/dev/null" . | toJson -}}
{{- end -}}

{{- define "vs.fluentdProbeCmd" -}}
{{- list "ruby" "-rnet/http" "-e" "r = Net::HTTP.get_response(URI('http://127.0.0.1:24220/api/plugins.json')); exit(r.is_a?(Net::HTTPSuccess) ? 0 : 1)" | toJson -}}
{{- end -}}
