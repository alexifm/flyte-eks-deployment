# Flyte Deployment

## Notes

- A bit opinionated:
  - Uses AWS EKS
  - Uses AWS Load Balancer for ingress
  - Uses OpenID for Auth\
    - Followed the Okta section in the [Flyte Auth Docs](https://docs.flyte.org/en/latest/deployment/configuration/auth_setup.html)
    - But uses self authorization and not external!
  - Uses AWS Secret Manager and [External Secrets](https://external-secrets.io)
  - Only supports running in a single AWS region for all parts of the deployment

## AWS Setup

0. You've set up an EKS cluster
1. Create `flyte-system-role` that has access to an S3 bucket you'll be using for flyte.
2. Follow this guide for setting up [IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
3. Create an RDS database using Postgres. Master username should be `flyteadmin`. Initial database name should be `flyteadmin`. Also set up its connectivity to be compatible with EKS (VPC, security groups, etc)
4. Follow this guide for prepping for ingress: https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/
5. Get a DNS name and a certificate. AWS Docs have this covered, for example here: https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html#request-public-console

If you need more detail, the old version of the deployment docs is helpful: https://web.archive.org/web/20220926215904/https://docs.flyte.org/en/latest/deployment/aws/manual.html

## External Secrets

This guide uses External Secrets. Follow [their guide](https://external-secrets.io/v0.7.2/introduction/getting-started/) for getting it set up.

## Python

It's recommended to use a virtual environment. Install the requirements with:

```
╰─❯ pip install -r requirements.txt
```

## Config

Set up the `flyte_deployment_config.yaml` file. See `flyte_deployment_config.yaml.tmpl`.

```
aws:
  # Your AWS Account number
  account_number: ...
  # AWS Region for this deployment
  account_region:
  # Name of the flyte system role
  flyte_system_role:
  # Host name for the RDS database
  rds_host: ...
  # S3 bucket name for flyte
  bucket_name: ...
ingress:
  # DNS host name set up with AWS Route 53
  dns_host: ...
  # Certificate ARN set up with ACM
  certificate_arn: ...
  # A group name to use for the ALB
  albGroupName: ...
auth:
  # OpenID Auth url
  open_id_url: ...
  # ClientID from the Auth IDP setup
  client_id: ...
data-plane:
  # Data plane cluster configuration
  clusters:
    - name: ...
      # Cluster ID, can be the same as the name
      id: ...
      # ID key for naming the cluster credentials secret in AWS SM
      secret_id: ...
      # Name of K8s context in Kubeconfig for the data plane deployment
      context: ...
control-plane:
  # Name of K8s context in Kubeconfig for the control plane deployment
  context: ...
  # Name of External Secrets SecretStore
  secret-store-name: secretstore
  # Name of service account SecretStore is going to use
  secret-store-service-account: flyteadmin
  # ID key for naming the database password secret in AWS SM
  database-secret-id: ...
```

Also, you will need to have ready a client secret you will use for authentication and
the password used for the Postgres database.

## Deploy

Run

```
╰─❯ nox -s deploy -- \
  --client-secret your-flyte-client-secret \
  --db-password your-database-password
```

Or run the individual steps:

```
╰─❯ nox -s create-user-settings -- --client-secret your-flyte-client-secret
╰─❯ nox -s deploy-data-plane
╰─❯ nox -s create-secret-store
╰─❯ nox -s create-data-plane-cluster-secrets
╰─❯ nox -s create-database-secret -- --db-password your-database-password
╰─❯ nox -s create-values-cluster-config-file
╰─❯ nox -s deploy-control-plane
```

## Interacting with Flyte

### Config

Set up an environment variable with the client secret used above or put it in a file
for flyte to access it.

```
admin:
  endpoint: dns:///<your dns name>
  authType: ClientSecret
  clientSecretEnvVar: FLYTECTL_SECRET
  # clientSecretLocation: /path/to/client/secret
logger:
  show-source: true
  level: 0
storage:
  type: s3
  connection:
    auth-type: iam
    region: <your region>
  container: <your s3 bucket for flyte>
```

### Setting up a Project

#### Create a Project

Taken from [here](https://docs.flyte.org/projects/flytectl/en/latest/gen/flytectl_create_project.html):

```
╰─❯ flytectl create project --file project.yaml
```

with `project.yaml`:

```
description: Project description
domains:
- id: dev
  name: dev
- id: qa
  name: qa
- id: prod
  name: prod
id: project
name: Project
```

You can use your own IDs and Names.

#### Cluster Resource Attributes

Taken from [here](https://docs.flyte.org/en/latest/deployment/configuration/general.html#cluster-resources)

```
╰─❯ flytectl update cluster-resource-attribute --attrFile cra.yaml
```

with `cra.yaml`:

```
attributes:
  projectQuotaCpu: "4"
  projectQuotaMemory: "3000Mi"
  defaultIamRole: <your flyte user role for this domain>
domain: dev
project: project
```

Create a `cra.yaml` file for each domain.

#### Execution Cluster Labels

Taken from [here](https://docs.flyte.org/en/latest/deployment/deployment/multicluster.html#configure-execution-cluster-labels)

```
╰─❯ flytectl update execution-cluster-label --attrFile ecl.yaml
```

with `ecl.yaml`:

```
domain: dev
project: project
value: dev
```

The `value` field should match one of the data plane cluster names in the
`data-plane.clusters` list in `flyte_deployment_config.yaml`.

Create a `ecl.yaml` file for each domain.

# Teardown

1. `helm uninstall flyte`
2. Delete namespaces (`flyte`, and all project namespaces). If needed, some dangling workflows need this step: https://rogulski.it/blog/kubernetes-stuck-resource-action/
3. `kubectl delete mutatingwebhookconfiguration flyte-pod-webhook`
