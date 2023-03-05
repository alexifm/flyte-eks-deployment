# flyte-binary

![Version: v1.3.0](https://img.shields.io/badge/Version-v1.3.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.16.0](https://img.shields.io/badge/AppVersion-1.16.0-informational?style=flat-square)

Chart for basic single Flyte executable deployment

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| clusterResourceTemplates.annotations | object | `{}` |  |
| clusterResourceTemplates.externalConfigMap | string | `""` |  |
| clusterResourceTemplates.inline | object | `{}` |  |
| clusterResourceTemplates.labels | object | `{}` |  |
| commonAnnotations | object | `{}` |  |
| commonLabels | object | `{}` |  |
| configuration.annotations | object | `{}` |  |
| configuration.auth.enabled | bool | `false` |  |
| configuration.auth.internal.clientSecret | string | `""` |  |
| configuration.auth.internal.clientSecretHash | string | `""` |  |
| configuration.auth.oidc.baseUrl | string | `""` |  |
| configuration.auth.oidc.clientId | string | `""` |  |
| configuration.auth.oidc.clientSecret | string | `""` |  |
| configuration.database.dbname | string | `"flyte"` |  |
| configuration.database.host | string | `"127.0.0.1"` |  |
| configuration.database.options | string | `"sslmode=disable"` |  |
| configuration.database.password | string | `""` |  |
| configuration.database.passwordPath | string | `""` |  |
| configuration.database.port | int | `5432` |  |
| configuration.database.username | string | `"postgres"` |  |
| configuration.externalConfigMap | string | `""` |  |
| configuration.inline | object | `{}` |  |
| configuration.labels | object | `{}` |  |
| configuration.logging.level | int | `1` |  |
| configuration.logging.plugins.cloudwatch.enabled | bool | `false` |  |
| configuration.logging.plugins.cloudwatch.templateUri | string | `""` |  |
| configuration.logging.plugins.custom | list | `[]` |  |
| configuration.logging.plugins.kubernetes.enabled | bool | `false` |  |
| configuration.logging.plugins.kubernetes.templateUri | string | `""` |  |
| configuration.logging.plugins.stackdriver.enabled | bool | `false` |  |
| configuration.logging.plugins.stackdriver.templateUri | string | `""` |  |
| configuration.storage.metadataContainer | string | `"my-organization-flyte-container"` |  |
| configuration.storage.provider | string | `"s3"` |  |
| configuration.storage.providerConfig.gcs.project | string | `"my-organization-gcp-project"` |  |
| configuration.storage.providerConfig.s3.accessKey | string | `""` |  |
| configuration.storage.providerConfig.s3.authType | string | `"iam"` |  |
| configuration.storage.providerConfig.s3.disableSSL | bool | `false` |  |
| configuration.storage.providerConfig.s3.endpoint | string | `""` |  |
| configuration.storage.providerConfig.s3.region | string | `"us-east-1"` |  |
| configuration.storage.providerConfig.s3.secretKey | string | `""` |  |
| configuration.storage.providerConfig.s3.v2Signing | bool | `false` |  |
| configuration.storage.userDataContainer | string | `"my-organization-flyte-container"` |  |
| deployment.annotations | object | `{}` |  |
| deployment.args | list | `[]` |  |
| deployment.command | list | `[]` |  |
| deployment.extraEnvVars | list | `[]` |  |
| deployment.extraEnvVarsConfigMap | string | `""` |  |
| deployment.extraEnvVarsSecret | string | `""` |  |
| deployment.extraPodSpec | object | `{}` |  |
| deployment.extraVolumeMounts | list | `[]` |  |
| deployment.extraVolumes | list | `[]` |  |
| deployment.genAdminAuthSecret.args | list | `[]` |  |
| deployment.genAdminAuthSecret.command | list | `[]` |  |
| deployment.image.pullPolicy | string | `"IfNotPresent"` |  |
| deployment.image.repository | string | `"ghcr.io/flyteorg/flyte-binary"` |  |
| deployment.image.tag | string | `"latest"` |  |
| deployment.initContainers | list | `[]` |  |
| deployment.labels | object | `{}` |  |
| deployment.lifecycleHooks | object | `{}` |  |
| deployment.livenessProbe | object | `{}` |  |
| deployment.podAnnotations | object | `{}` |  |
| deployment.podLabels | object | `{}` |  |
| deployment.podSecurityContext.enabled | bool | `false` |  |
| deployment.podSecurityContext.fsGroup | int | `65534` |  |
| deployment.podSecurityContext.runAsGroup | int | `65534` |  |
| deployment.podSecurityContext.runAsUser | int | `65534` |  |
| deployment.readinessProbe | object | `{}` |  |
| deployment.resources.limits.memory | string | `"1Gi"` |  |
| deployment.resources.requests.cpu | int | `1` |  |
| deployment.sidecars | list | `[]` |  |
| deployment.startupProbe | object | `{}` |  |
| deployment.waitForDB.args | list | `[]` |  |
| deployment.waitForDB.command | list | `[]` |  |
| deployment.waitForDB.image.pullPolicy | string | `"IfNotPresent"` |  |
| deployment.waitForDB.image.repository | string | `"postgres"` |  |
| deployment.waitForDB.image.tag | string | `"15-alpine"` |  |
| fullnameOverride | string | `""` |  |
| ingress.commonAnnotations | object | `{}` |  |
| ingress.create | bool | `false` |  |
| ingress.grpcAnnotations | object | `{}` |  |
| ingress.host | string | `""` |  |
| ingress.httpAnnotations | object | `{}` |  |
| ingress.labels | object | `{}` |  |
| nameOverride | string | `""` |  |
| rbac.annotations | object | `{}` |  |
| rbac.create | bool | `true` |  |
| rbac.extraRules | list | `[]` |  |
| rbac.labels | object | `{}` |  |
| service.annotations | object | `{}` |  |
| service.clusterIP | string | `""` |  |
| service.externalTrafficPolicy | string | `"Cluster"` |  |
| service.extraPorts | list | `[]` |  |
| service.labels | object | `{}` |  |
| service.loadBalancerIP | string | `""` |  |
| service.loadBalancerSourceRanges | list | `[]` |  |
| service.nodePorts.grpc | string | `""` |  |
| service.nodePorts.http | string | `""` |  |
| service.ports.grpc | string | `""` |  |
| service.ports.http | string | `""` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.labels | object | `{}` |  |
| serviceAccount.name | string | `""` |  |

