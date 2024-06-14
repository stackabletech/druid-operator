#!/bin/sh

cat << 'EOF' | ldapadd -H ldap://localhost:1389 -D cn=admin,dc=example,dc=org -w "admin-pw withSpace$%\" &&} §"
dn: uid=alice,ou=users,dc=example,dc=org
uid: alice
cn: alice
sn: alice
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
homeDirectory: /home/alice
uidNumber: 3
gidNumber: 3
userPassword: alice
EOF
