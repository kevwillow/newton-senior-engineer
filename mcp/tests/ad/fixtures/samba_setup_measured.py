"""Bytes measured from the write setup on the real Samba DC.

Source: sdc1.lab2.newton.test, Samba 4.22.11, 2026-11-09.
These are command outputs, including the LDIF continuation bytes.
The one exception is TESTPARM_REALM, which is marked below.
"""

DOMAIN_INFO = b"""Forest           : lab2.newton.test
Domain           : lab2.newton.test
Netbios domain   : NEWTONLAB2
DC name          : sdc1.lab2.newton.test
DC netbios name  : SDC1
Server site      : Default-First-Site-Name
Client site      : Default-First-Site-Name
"""

#: The realm of that domain, in the form samba-tool testparm prints it.
#: This output was NOT measured on the DC: the realm of the domain is
#: its DNS name, uppercased, and the script falls back to the Domain
#: line of samba-tool domain info when testparm prints nothing.
TESTPARM_REALM = b"LAB2.NEWTON.TEST\n"

ROOT_DSE = b"""# record 1
dn: 
dsServiceName: CN=NTDS Settings,CN=SDC1,CN=Servers,CN=Default-First-Site-Name,
 CN=Sites,CN=Configuration,DC=lab2,DC=newton,DC=test

# returned 1 records
# 1 entries
# 0 referrals
"""

FSMO_ROLE_OWNER = b"""# record 1
dn: DC=lab2,DC=newton,DC=test
fSMORoleOwner: CN=NTDS Settings,CN=SDC1,CN=Servers,CN=Default-First-Site-Name
 ,CN=Sites,CN=Configuration,DC=lab2,DC=newton,DC=test

# returned 1 records
# 1 entries
# 0 referrals
"""

OPS_SID = "S-1-5-21-111111111-222222222-333333333-501"
DOMAIN_SID = "S-1-5-21-111111111-222222222-333333333"
DOMAIN_USERS_SID = DOMAIN_SID + "-513"

OBJECT_SID = (
    b"# record 1\n"
    b"dn: CN=newton-ops,CN=Users,DC=lab2,DC=newton,DC=test\n"
    + b"objectSid: "
    + OPS_SID.encode("ascii")
    + b"\n"
)

TOKEN_GROUPS = (
    b"# record 1\n"
    b"dn: CN=newton-ops,CN=Users,DC=lab2,DC=newton,DC=test\n"
    b"tokenGroups: S-1-5-21-111111111-222222222-333333333-513\n"
    b"tokenGroups: S-1-5-21-111111111-222222222-333333333-515\n"
)

USER_CLASS_GUID = "bf967aba-0de6-11d0-a285-00aa003049e2"
UAC_ATTRIBUTE_GUID = "bf967a68-0de6-11d0-a285-00aa003049e2"
GET_CHANGES_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_ALL_GUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_FILTERED_GUID = "89e95b76-444d-4c62-991a-0facbeda640c"

SCHEMA_USER = (
    b"dn: CN=User,CN=Schema,CN=Configuration,DC=lab2,DC=newton,DC=test\n"
    b"schemaIDGUID: bf967aba-0de6-11d0-a285-00aa003049e2\n"
)

SCHEMA_UAC = (
    b"dn: CN=User-Account-Control,CN=Schema,CN=Configuration,DC=lab2,DC=newton,DC=test\n"
    b"schemaIDGUID: bf967a68-0de6-11d0-a285-00aa003049e2\n"
)

EXTENDED_RIGHTS = b"""dn: CN=DS-Replication-Get-Changes,CN=Extended-Rights,CN=Configuration,DC=lab2,DC=newton,DC=test
rightsGuid: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2

dn: CN=DS-Replication-Get-Changes-All,CN=Extended-Rights,CN=Configuration,DC=lab2,DC=newton,DC=test
rightsGuid: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

dn: CN=DS-Replication-Get-Changes-In-Filtered-Set,CN=Extended-Rights,CN=Configuration,DC=lab2,DC=newton,DC=test
rightsGuid: 89e95b76-444d-4c62-991a-0facbeda640c
"""

PRESENT_OBJECT_ACE = (
    "descriptor for OU=Users,DC=lab2,DC=newton,DC=test:\n"
    "O:SYG:SYD:(OA;CI;WP;bf967a68-0de6-11d0-a285-00aa003049e2;"
    "bf967aba-0de6-11d0-a285-00aa003049e2;LG)\n"
).encode("ascii")

DU_REPLICATION_ACE = (
    "descriptor for DC=lab2,DC=newton,DC=test:\n"
    "O:SYG:SYD:(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;DU)\n"
).encode("ascii")

DU_ALL_EXTENDED_ACE = (
    "descriptor for DC=lab2,DC=newton,DC=test:\n"
    "O:SYG:SYD:(A;;CR;;;DU)\n"
).encode("ascii")

WIDENED_ACE = (
    "descriptor for OU=Users,DC=lab2,DC=newton,DC=test:\n"
    "O:SYG:SYD:(A;CI;WP;;;LG)\n"
).encode("ascii")
