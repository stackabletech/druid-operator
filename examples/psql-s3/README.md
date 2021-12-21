A PostgreSQL database is required, you can spin up a PostgreSQL database with the bitnami PostgreSQL helm chart.
Add the bitname repository:

    helm repo add bitnami https://charts.bitnami.com/bitnami

And setup the Postgres database:

    helm install druid bitnami/postgresql \
    --set postgresqlUsername=druid \
    --set postgresqlPassword=druid \
    --set postgresqlDatabase=druid