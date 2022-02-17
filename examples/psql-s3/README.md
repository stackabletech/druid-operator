A PostgreSQL database is required, you can spin up a PostgreSQL database with the bitnami PostgreSQL helm chart.
Add the bitname repository:

    helm repo add bitnami https://charts.bitnami.com/bitnami

And setup the Postgres database:

    helm install druid bitnami/postgresql \
    --version=11 \
    --set auth.username=druid \
    --set auth.password=druid \
    --set auth.database=druid

Make sure to adapt the S3 secret in `./druid-cluster.yaml` with your credentials:

    apiVersion: v1
    kind: Secret
    metadata:
      name: s3-credentials
    stringData:
      accessKeyId: YOUR_VALID_ACCESS_KEY_ID_HERE
      secretAccessKey: YOUR_SECRET_ACCES_KEY_THATBELONGS_TO_THE_KEY_ID_HERE
