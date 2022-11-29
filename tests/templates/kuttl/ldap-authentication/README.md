# LDAP Authenticator Test

This test sets up the following LDAP users:

- `admin` : for Druid administration. Part of the `admin` group.
- `druid_system` : for Druid internal communications, also part of the `admin` group.
- `alice` : not part of the `admin` group

See `authcheck.py` for examples of authorized access.
