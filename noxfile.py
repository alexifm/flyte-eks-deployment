"""Infima cli tool."""
import argparse
import base64
import json
import pathlib
import tempfile
from typing import Dict, List

import bcrypt
import boto3
import nox
import yaml
from kubeconfig import KubeConfig
from kubernetes import client, config, utils
from nox import Session, session

nox.options.reuse_existing_virtualenvs = True

config.load_kube_config()
conf = KubeConfig()


with open("flyte_deployment_config.yaml", "r") as fp:
    deploy_config = yaml.safe_load(fp)


############################################################


def _parse_cluster_names(cluster_names: List[str]) -> List[Dict[str, str]]:
    clusters: List[Dict[str, str]]
    if cluster_names is None:
        clusters = deploy_config["data-plane"]["clusters"]
    else:
        all_clusters = deploy_config["data-plane"]["clusters"]
        clusters = [cl for cl in all_clusters if cl["name"] in cluster_names]

    return clusters


def create_k8s_resource_from_string_template(
    tmpl: str,
    format_kwargs: Dict[str, str],
    context: str,
) -> None:
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir = pathlib.Path(tmpdirname)

        f = tmpdir / f"manifest.yaml"
        with open(f, "w") as fp:
            fp.write(tmpl.format(**format_kwargs))

        k8s_client = config.new_client_from_config(context=context)
        utils.create_from_yaml(k8s_client, str(f), verbose=True)


def create_aws_secret(
    secret_id: str,
    secret_data: Dict[str, str],
    region: str,
) -> None:
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region,
    )
    data_string = json.dumps(secret_data, separators=(",", ":"))
    _ = client.put_secret_value(
        SecretId=secret_id,
        SecretString=data_string,
    )


EXTERNAL_SECRETS_TMPL = """
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {name}
  namespace: flyte
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: {secret_store_name}
    kind: SecretStore
  target:
    creationPolicy: Owner
  dataFrom:
  - extract:
      key: {secret_id}
"""


def create_external_secret(
    name: str,
    secret_store_name: str,
    secret_id: str,
    context: str,
) -> None:
    create_k8s_resource_from_string_template(
        tmpl=EXTERNAL_SECRETS_TMPL,
        format_kwargs={
            "name": name,
            "secret_store_name": secret_store_name,
            "secret_id": secret_id,
        },
        context=context,
    )


############################################################


VALUES_USER_SETTINGS_TMPL = """
userSettings:
  # eks
  accountNumber: {account_number}
  accountRegion: {account_region}
  flyteSystemRole: {flyte_system_role}
  rdsHost: {rds_host}
  bucketName: {bucket_name}
  # ingress
  dnsHost: {dns_host}
  certificateArn: {certificate_arn}
  albGroupName: {alb_group_name}
  # auth
  openIdUrl: {open_id_url}
  clientID: {client_id}
  clientSecret: {client_secret}
  clientSecretEncoded: {client_secret_encoded}
"""


@session(name="create-user-settings")
def create_user_settings(session: Session) -> None:
    parser = argparse.ArgumentParser(prog=f"nox -s {session.name} --")
    parser.add_argument("--client-secret", required=True)
    args, _ = parser.parse_known_args(session.posargs)

    client_secret = args.client_secret
    client_secret_encoded = base64.b64encode(
        bcrypt.hashpw(
            client_secret.encode("utf-8"),
            bcrypt.gensalt(6),
        )
    ).decode()

    with open("values-user-settings.yaml", "w") as fp:
        fp.write(
            VALUES_USER_SETTINGS_TMPL.format(
                **deploy_config["aws"],
                **deploy_config["ingress"],
                **deploy_config["auth"],
                client_secret=client_secret,
                client_secret_encoded=client_secret_encoded,
            )
        )


############################################################


def deploy_data_plane_on_cluster(cluster: Dict[str, str]) -> None:
    conf.use_context(cluster["context"])

    cmd = [
        # fmt: off
        "helm", "upgrade", "flyte", "./flyte-core", "--install",
        "--values", "values.yaml",
        "--values", "values-eks.yaml",
        "--values", "values-dataplane.yaml",
        "--create-namespace", "--namespace", "flyte",
        # fmt: on
    ]
    session.run(*cmd, external=True)


@session(name="deploy-data-plane")
def deploy_data_plane(session: Session) -> None:
    parser = argparse.ArgumentParser(prog=f"nox -s {session.name} --")
    parser.add_argument("--cluster-names", nargs="*")
    args, _ = parser.parse_known_args(session.posargs)

    curr_context = conf.current_context()

    clusters = _parse_cluster_names(args.cluster_names)

    for cluster in clusters:
        deploy_data_plane_on_cluster(cluster)

    conf.use_context(curr_context)


############################################################

SECRET_STORE_TMPL = """
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: {secret_store_name}
  namespace: flyte
spec:
  provider:
    aws:
      service: SecretsManager
      region: {region}
      auth:
        jwt:
          serviceAccountRef:
            name: {service_account}
"""


@session(name="create-secret-store")
def create_secret_store(session: Session) -> None:
    ctl_config = deploy_config["control-plane"]
    format_kwargs = {
        "secret_store_name": ctl_config["secret-store-name"],
        "region": deploy_config["aws"]["account_region"],
        "service_account": ctl_config["secret-store-service-account"],
    }

    create_k8s_resource_from_string_template(
        tmpl=SECRET_STORE_TMPL,
        format_kwargs=format_kwargs,
        context=ctl_config["context"],
    )


############################################################


def get_data_plane_cluster_credentials(cluster: Dict[str, str]) -> Dict[str, str]:
    k8s_client = config.new_client_from_config(context=cluster["context"])
    api = client.CoreV1Api(k8s_client)
    secret_list = api.list_namespaced_secret("flyte")
    for secret in secret_list.items:
        if secret.metadata.name.startswith("flyteadmin-token"):
            break

    cacert = base64.b64decode(secret.data["ca.crt"]).decode()
    token = base64.b64decode(secret.data["token"]).decode()
    return {"cacert": cacert, "token": token}


def cluster_credentials_external_secret_name(cluster_name: str) -> str:
    return f"cluster-credentials-{cluster_name}"


def create_data_plane_credentials_external_secret(cluster: Dict[str, str]) -> None:
    create_external_secret(
        name=cluster_credentials_external_secret_name(cluster["name"]),
        secret_store_name=deploy_config["control-plane"]["secret-store-name"],
        secret_id=cluster["secret_id"],
        context=cluster["context"],
    )


@session(name="create-data-plane-cluster-secrets")
def create_data_plane_cluster_secrets(session: Session) -> None:
    parser = argparse.ArgumentParser(prog=f"nox -s {session.name} --")
    parser.add_argument("--cluster-names", nargs="*")
    args, _ = parser.parse_known_args(session.posargs)

    curr_context = conf.current_context()

    clusters = _parse_cluster_names(args.cluster_names)

    for cluster in clusters:
        secret_data = get_data_plane_cluster_credentials(cluster)
        create_aws_secret(
            cluster["secret_id"],
            secret_data,
            deploy_config["aws"]["account_region"],
        )
        create_data_plane_credentials_external_secret(cluster)

    conf.use_context(curr_context)


############################################################


def create_database_external_secret() -> None:
    create_external_secret(
        name="db-pass",
        secret_store_name=deploy_config["control-plane"]["secret-store-name"],
        secret_id=deploy_config["control-plane"]["database-secret-id"],
        context=deploy_config["control-plane"]["context"],
    )


@session(name="create-database-secret")
def create_database_secret(session: Session) -> None:
    parser = argparse.ArgumentParser(prog=f"nox -s {session.name} --")
    parser.add_argument("--db-password", required=True)
    args, _ = parser.parse_known_args(session.posargs)

    secret_data = {"pass.txt": args.db_password}
    create_aws_secret(
        deploy_config["control-plane"]["database-secret-id"],
        secret_data,
        deploy_config["aws"]["account-region"],
    )
    create_database_external_secret()


############################################################


def get_cluster_endpoint(context: str) -> str:
    d = conf.view()
    for con in d["contexts"]:
        if con["name"] == context:
            break
    for cl in d["clusters"]:
        if cl["name"] == con["context"]["cluster"]:
            break
    return cl["cluster"]["server"]


@session(name="create-values-cluster-config-file")
def create_values_cluster_config_file(session: Session) -> None:
    parser = argparse.ArgumentParser(prog=f"nox -s {session.name} --")
    parser.add_argument("--cluster-names", nargs="+")
    args, _ = parser.parse_known_args(session.posargs)

    clusters = _parse_cluster_names(args.cluster_names)

    spec = {
        "flyteadmin": {
            "additionalVolumes": [],
            "additionalVolumeMounts": [],
        },
        "configmap": {
            "clusters": {
                "labelClusterMap": {},
                "clusterConfigs": [],
            }
        },
    }

    for cluster in clusters:
        name = cluster["name"]
        _id = cluster["id"]
        context = cluster["context"]
        endpoint = get_cluster_endpoint(context)

        credential_name = cluster_credentials_external_secret_name(name)
        mount_path = f"/etc/credentials_{name}/"

        add_vol = {
            "name": credential_name,
            "secret": {"secretName": credential_name},
        }
        add_vol_mnt = {
            "name": credential_name,
            "mountPath": mount_path,
        }
        label_map = {name: [{"id": _id, "weight": 1}]}
        config = {
            "name": _id,
            "endpoint": endpoint,
            "enabled": True,
            "auth": {
                "type": "file_path",
                "tokenPath": f"{mount_path}token",
                "certPath": f"{mount_path}cacert",
            },
        }

        spec["flyteadmin"]["additionalVolumes"].append(add_vol)
        spec["flyteadmin"]["additionalVolumeMounts"].append(add_vol_mnt)
        spec["configmap"]["clusters"]["labelClusterMap"].update(label_map)
        spec["configmap"]["clusters"]["clusterConfigs"].append(config)

    with open("values-cluster-config.yaml", "w") as fp:
        yaml.safe_dump(spec, fp)


############################################################


@session(name="deploy-control-plane")
def deploy_control_plane(session: Session) -> None:
    curr_context = conf.current_context()
    conf.use_context(deploy_config["control-plane"]["context"])

    cmd = [
        # fmt: off
        "helm", "upgrade", "flyte", "./flyte-core", "--install",
        "--values", "values.yaml",
        "--values", "values-eks.yaml",
        "--values", "values-cluster-config.yaml",
        "--values", "values-ingress.yaml",
        "--values", "values-auth.yaml",
        "--values", "values-user-settings.yaml",
        "--create-namespace", "--namespace", "flyte",
        # fmt: on
    ]
    session.run(*cmd, external=True)

    conf.use_context(curr_context)


############################################################


@session()
def deploy(session: Session) -> None:
    parser = argparse.ArgumentParser(prog=f"nox -s {session.name} --")
    parser.add_argument("--client-secret", required=True)
    parser.add_argument("--db-password", required=True)
    parser.add_argument("--cluster-names", nargs="+")
    args, _ = parser.parse_known_args(session.posargs)

    session.notify(
        "create-user-settings",
        ["--client-secret", args.client_secret],
    )
    session.notify(
        "deploy-data-plane",
        ["--cluster-names", *args.cluster_names],
    )
    session.notify("create-secret-store")
    session.notify(
        "create-data-plane-cluster-secrets",
        ["--cluster-names", *args.cluster_names],
    )
    session.notify(
        "create-database-secret",
        ["--db-password", args.db_password],
    )
    session.notify(
        "create-values-cluster-config-file",
        ["--cluster-names", *args.cluster_names],
    )
    session.notify("deploy-control-plane")
