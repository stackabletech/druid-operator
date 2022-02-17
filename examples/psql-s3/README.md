A PostgreSQL database is required, you can spin up a PostgreSQL database with the bitnami PostgreSQL helm chart.
Add the bitname repository:

    helm repo add bitnami https://charts.bitnami.com/bitnami

And setup the Postgres database:

    helm install druid bitnami/postgresql \
    --set postgresqlUsername=druid \
    --set postgresqlPassword=druid \
    --set postgresqlDatabase=druid

Make sure to adapt the S3 secret in `./druid-cluster.yaml` with your credentials:

    apiVersion: v1
    kind: Secret
    metadata:
      name: s3-credentials
    stringData:
      accessKeyId: YOUR_VALID_ACCESS_KEY_ID_HERE
      secretAccessKey: YOUR_SECRET_ACCES_KEY_THATBELONGS_TO_THE_KEY_ID_HERE