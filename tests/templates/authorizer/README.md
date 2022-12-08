# Authorizer Test

Required Operators:

- Zookeeper
- Druid
- RegoRule
- OPA

1. Deploy Zookeeper Cluster
2. Deploy OPA Cluster + RegoRule
3. Deploy Druid Cluster
4. Setup Test Container
5. Run Auth Test:
    - Create two test users: Alice, Eve
    - Run HTTP requests to test if authentication + authorization works:
      - unauthenticated user should get a 401
      - unauthorized user should get a 403
      - authorized user should get the "normal" response

To run only this test, use `kuttl test tests/opa`
