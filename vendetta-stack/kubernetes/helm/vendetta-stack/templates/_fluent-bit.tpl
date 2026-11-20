{{/*
Traces: CONTRACT section 2 (Fluent Bit ports, PKI, volumes), section 8.3 (routing); fluent-bit/RUNTIME.md (K8s).
vs.fluentBitPod renders the pod spec shared by the node DaemonSet and the fluent-bit-shared Deployment.
  distroless: initContainer on the -debug image renders enabled.d (entrypoint.sh --render-only) and creates the state dirs.
  debug:      entrypoint.sh runs as in compose (renders, validates, rotates the ollama safety file).
args: root, shared (bool: mounts the shared RWX log volumes instead of node paths)
*/}}
{{- define "vs.fluentBitEnv" -}}
{{- $fb := .root.Values.fluentBit -}}
{{- $leg := $fb.legs -}}
{{- $env := dict
  "FLB_LOG_LEVEL" $fb.logLevel
  "CS3_EPS_LIMIT" $fb.epsLimit
  "CS3_MESSAGE_MAX_CHARS" .root.Values.config.messageMaxChars
  "CS3_HEALTH_SCRAPE_SEC" $fb.healthScrapeSeconds
  "ERROW_TUI_PORT" $fb.tuiPort
  "ERROW_REPORTS_DIR" "/var/log/errow/reports"
  "ERROW_SHIPPER_STATUS_FILE" "/var/lib/errow-shipper/status.json"
  "CAIDO_LOG_GLOB" "/var/log/errow/caido/*.log"
  "FLB_FORWARD_TLS" $fb.forwardTls
  "FLB_FORWARD_TLS_VERIFY" $fb.forwardTlsVerify
  "FLB_FORWARD_TLS_CA_FILE" "/pki/ca.crt"
  "FLB_FORWARD_TLS_CRT_FILE" "/pki/fluent-bit.crt"
  "FLB_FORWARD_TLS_KEY_FILE" "/pki/fluent-bit.key"
  "FLB_FORWARD_STORAGE_LIMIT" $fb.forwardStorageLimit
  "FLB_SYSLOG_PORT" "5140"
  "FLB_JOURNAL_PATH" $fb.hostLogs.journalPath
  "CS3_HOST_LOGS" "false"
  "CS3_CONSOLE_ENABLED" $leg.console.enabled
  "CS3_HOST" $leg.console.host
  "CS3_PORT" $leg.console.port
  "CS3_TLS" $leg.console.tls
  "CS3_CA_FILE" "/pki/ca.crt"
  "CS3_ESOC_ENABLED" $leg.esoc.enabled
  "CS3_ESOC_HOST" $leg.esoc.host
  "CS3_ESOC_PORT" $leg.esoc.port
  "CS3_ESOC_GRPC" $leg.esoc.grpc
  "CS3_ESOC_TLS" $leg.esoc.tls
  "CS3_ESOC_CA_FILE" "/pki/ca.crt"
  "CS3_ESOC_CERT_FILE" "/pki/fluent-bit.crt"
  "CS3_ESOC_KEY_FILE" "/pki/fluent-bit.key"
  "CS3_SIEM_ENABLED" $leg.siem.enabled
  "CS3_SIEM_HOST" $leg.siem.host
  "CS3_SIEM_PORT" $leg.siem.port
  "CS3_SIEM_URI" $leg.siem.uri
  "CS3_SIEM_TLS" $leg.siem.tls
  "CS3_SIEM_CA_FILE" "/pki/ca.crt"
  "CS3_SIEM_FORMAT" $leg.siem.format
  "CS3_SIEM_AUTH_SCHEME" $leg.siem.authScheme
  "CS3_MANAGER_ENABLED" $leg.manager.enabled
  "CS3_MANAGER_HOST" $leg.manager.host
  "CS3_MANAGER_PORT" $leg.manager.port
  "FLB_MANAGER_ALERTS_PATH" "/var/vendetta/logs/alerts/alerts.json"
  "CS3_ALERT_DEDUP_WINDOW_S" $fb.alertDedupWindowSeconds -}}
{{ include "vs.profileEnv" .root }}
{{ include "vs.env" $env }}
{{- end -}}

{{- define "vs.fluentBitSecretEnv" -}}
{{- $leg := .root.Values.fluentBit.legs -}}
{{- if or $leg.console.enabled $leg.manager.enabled }}
- name: CS3_INGEST_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .root.Values.secrets.legsSecret }}
      key: {{ $leg.console.ingestKeyKey }}
{{- end }}
{{- if $leg.siem.enabled }}
- name: CS3_SIEM_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .root.Values.secrets.legsSecret }}
      key: {{ $leg.siem.tokenKey }}
{{- end }}
{{- end -}}

{{- define "vs.fluentBitPod" -}}
{{- $root := .root -}}
{{- $fb := $root.Values.fluentBit -}}
{{- $distroless := eq $fb.variant "distroless" -}}
{{- $hostLogs := and (not .shared) $fb.hostLogs.enabled -}}
{{ include "vs.podDefaults" (dict "root" $root) }}
terminationGracePeriodSeconds: 30
securityContext:
{{- if $hostLogs }}
  runAsNonRoot: false
  runAsUser: 0
  runAsGroup: 0
  seccompProfile:
    type: RuntimeDefault
{{- else }}
{{ include "vs.podSecurity" (dict "uid" 10001) | indent 2 }}
{{- end }}
{{- if .shared }}
{{ include "vs.scheduling" (dict "root" $root "cfg" (dict) "component" "fluent-bit-shared" "co" true) }}
{{- else }}
{{ include "vs.scheduling" (dict "root" $root "cfg" $fb "component" "fluent-bit") }}
{{- end }}
{{- if $distroless }}
initContainers:
  - name: render
    image: {{ include "vs.image" (dict "root" $root "img" $root.Values.images.fluentBit) }}
    imagePullPolicy: {{ $root.Values.global.imagePullPolicy }}
    command: ["bash", "-ec", "/etc/fluent-bit/entrypoint.sh --render-only /rendered && mkdir -p /var/log/fluent-bit/storage /var/log/fluent-bit/db"]
    env:
{{ include "vs.fluentBitEnv" (dict "root" $root) | indent 6 }}
    securityContext:
{{ include "vs.containerSecurity" (dict) | indent 6 }}
    resources:
      requests: {cpu: 50m, memory: 32Mi}
      limits: {cpu: 250m, memory: 64Mi}
    volumeMounts:
      - {name: config, mountPath: /etc/fluent-bit, readOnly: true}
      - {name: enabled, mountPath: /rendered}
      - {name: state, mountPath: /var/log/fluent-bit}
      {{- if .shared }}
      {{- if $root.Values.errow.enabled }}
      - {name: errow-ndjson, mountPath: /var/log/errow, readOnly: true}
      {{- end }}
      {{- else if $hostLogs }}
      - {name: host-journal, mountPath: {{ $fb.hostLogs.journalPath }}, readOnly: true}
      {{- end }}
{{- end }}
containers:
  - name: fluent-bit
    image: {{ include "vs.image" (dict "root" $root "img" (ternary $root.Values.images.fluentBitDistroless $root.Values.images.fluentBit $distroless)) }}
    imagePullPolicy: {{ $root.Values.global.imagePullPolicy }}
    {{- if $distroless }}
    command: ["/fluent-bit/bin/fluent-bit"]
    args: ["-c", "/etc/fluent-bit/fluent-bit.conf"]
    {{- else }}
    command: ["/etc/fluent-bit/entrypoint.sh"]
    {{- end }}
    env:
{{ include "vs.fluentBitEnv" (dict "root" $root) | indent 6 }}
      - {name: CS3_HOSTNAME, valueFrom: {fieldRef: {fieldPath: spec.nodeName}}}
      - {name: CS3_AGENT_ID, value: {{ ternary "fluent-bit-shared" "fluent-bit-$(CS3_HOSTNAME)" .shared | quote }}}
{{ include "vs.fluentBitSecretEnv" (dict "root" $root) | indent 6 }}
    ports:
      - {name: http, containerPort: 2020}
      - {name: events, containerPort: 9880}
      - {name: forward, containerPort: 24224}
      - {name: tui, containerPort: {{ $fb.tuiPort }}}
    startupProbe:
      httpGet: {path: /api/v1/health, port: http}
      periodSeconds: 5
      failureThreshold: 24
    readinessProbe:
      httpGet: {path: /api/v1/health, port: http}
      periodSeconds: 10
      timeoutSeconds: 3
      failureThreshold: 3
    livenessProbe:
      httpGet: {path: /api/v1/health, port: http}
      periodSeconds: 20
      timeoutSeconds: 3
      failureThreshold: 6
    securityContext:
{{ include "vs.containerSecurity" (dict "add" (ternary (list "DAC_READ_SEARCH") (list) $hostLogs)) | indent 6 }}
    resources:
{{ toYaml $fb.resources | indent 6 }}
    volumeMounts:
      - {name: config, mountPath: /etc/fluent-bit, readOnly: true}
      - {name: enabled, mountPath: /etc/fluent-bit/enabled.d}
      - {name: pki, mountPath: /pki, readOnly: true}
      - {name: state, mountPath: /var/log/fluent-bit}
      {{- if .shared }}
      {{- if $root.Values.errow.enabled }}
      - {name: errow-ndjson, mountPath: /var/log/errow, readOnly: true}
      - {name: errow-shipper-state, mountPath: /var/lib/errow-shipper, readOnly: true}
      {{- end }}
      {{- if $root.Values.manager.enabled }}
      - {name: vendetta-logs, mountPath: /var/vendetta/logs, readOnly: true}
      {{- end }}
      {{- else if $hostLogs }}
      - {name: host-journal, mountPath: {{ $fb.hostLogs.journalPath }}, readOnly: true}
      {{- end }}
volumes:
  - name: config
    configMap:
      name: fluent-bit-config
      defaultMode: 0555
      items:
{{ include "vs.treeItems" (dict "root" $root "dir" "fluent-bit") | indent 8 }}
{{ include "vs.pkiVolume" (dict "root" $root "certs" (list (dict "svc" "fluent-bit"))) | indent 2 }}
  - name: enabled
    emptyDir: {}
  - name: state
    emptyDir:
      sizeLimit: {{ $fb.stateSizeLimit }}
  {{- if .shared }}
  {{- if $root.Values.errow.enabled }}
  - name: errow-ndjson
    persistentVolumeClaim: {claimName: errow-ndjson, readOnly: true}
  - name: errow-shipper-state
    persistentVolumeClaim: {claimName: errow-shipper-state, readOnly: true}
  {{- end }}
  {{- if $root.Values.manager.enabled }}
  - name: vendetta-logs
    persistentVolumeClaim: {claimName: vendetta-logs, readOnly: true}
  {{- end }}
  {{- else if $hostLogs }}
  - name: host-journal
    hostPath: {path: {{ $fb.hostLogs.journalPath }}, type: Directory}
  {{- end }}
{{- end -}}
