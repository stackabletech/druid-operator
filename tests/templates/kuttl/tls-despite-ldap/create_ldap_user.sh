#!/bin/sh

# To check the existing users
# ldapsearch -H ldap://localhost:1389 -D cn=admin,dc=example,dc=org -w admin -b ou=users,dc=example,dc=org

# To check the new user
# ldapsearch -H ldap://localhost:1389 -D cn=integrationtest,ou=users,dc=example,dc=org -w integrationtest -b ou=users,dc=example,dc=org

cat << 'EOF' | ldapadd -H ldap://localhost:1389 -D cn=admin,dc=example,dc=org -w admin
dn: ou=Groups,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: Groups

dn: uid=admin,ou=Users,dc=example,dc=org
uid: admin
cn: admin
sn: admin
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
homeDirectory: /home/admin
uidNumber: 1
gidNumber: 1
userPassword: admin

dn: uid=druid_system,ou=Users,dc=example,dc=org
uid: druid_system
cn: druid_system
sn: druid_system
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
homeDirectory: /home/druid_system
uidNumber: 2
gidNumber: 2
userPassword: druidsystem

dn: cn=admin,ou=Groups,dc=example,dc=org
objectClass: groupOfUniqueNames
cn: admin
description: Admin users
uniqueMember: uid=admin,ou=Users,dc=example,dc=org
uniqueMember: uid=druid_system,ou=Users,dc=example,dc=org

dn: uid=alice,ou=Users,dc=example,dc=org
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
