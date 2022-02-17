A PostgreSQL database is required, you can spin up a PostgreSQL database with the bitnami PostgreSQL helm chart.
Add the bitname repository:

    helm repo add bitnami https://charts.bitnami.com/bitnami

And setup the Postgres database:

    helm install druid bitnami/postgresql \
    --version=11 \
    --set auth.username=druid \
    --set auth.password=druid \
    --set auth.database=druid