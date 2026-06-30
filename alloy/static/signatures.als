/*
signatures.als - Alloy sig declarations for the Bitwarden access-control model

Hand-written

Each sig corresponds to one SQL table. Only access-control relevant columns are
modeled. Data fields are omitted.

Field naming: SQL columns are lowercased or given short readable
names.

Alloy version: 6
*/

module static/signatures

open static/enums


/*
OrgKey - token representing the org symmetric key for one OrganizationUser
Presence/absence drives the Confirmed-implies-Key invariant in facts.als.
The Key column value is irrelevant to access control, only presence matters.
*/

sig OrgKey {}


/*
Bool - two-valued type for SQL BIT columns.
Used for: Organization.Enabled, Organization.AllowAdminAccessToAllCollectionItems,
 CollectionUser/CollectionGroup ReadOnly, HidePasswords, Manage flags
*/

abstract sig Bool {}
one sig True, False extends Bool {}



-- User — SQL table: dbo.User
-- Models identity only, no fields needed for access-control predicates
sig User {}


/*
Organization - table: dbo.Organization
Two flags are access control relevant:
  enabled - org kill-switch; disabled orgs block all cipher access.
  allowAdminAccess - admin bypass (AllowAdminAccessToAllCollectionItems);
  applied at the C# service layer, not in the TVF
*/

sig Organization {
    -- SQL: Enabled BIT NOT NULL
    enabled: one Bool,
    -- SQL: AllowAdminAccessToAllCollectionItems BIT NOT NULL
    allowAdminAccess: one Bool
}


/*
Cipher - SQL table: dbo.Cipher
Ownership is modeled as a disjoint union: a Cipher is owned by exactly one
User (personal cipher) or exactly one Organization (org cipher)
See CipherOwnerIsExclusive in facts.als.
*/

sig Cipher {
    owner: one (User + Organization)
}

/*
Collection - SQL table: dbo.Collection
A named grouping of org ciphers. Access to ciphers is granted via
CollectionUser (direct) or CollectionGroup (via group membership).
*/

sig Collection {
    -- SQL: OrganizationId NOT NULL
    org: one Organization,
    -- Derived from junction table: dbo.CollectionCipher
    -- Rendered as a relation on Collection rather than a separate sig.
    ciphers: set Cipher
}

/*
OrganizationUser — SQL table: dbo.OrganizationUser
The membership record linking a User to an Organization.
  memberUser is absent (lone) while status = Invited (UserId is NULL in SQL).
  key is absent (lone) until status = Confirmed (key exchange has happened).
*/
sig OrganizationUser {
    -- SQL: OrganizationId NOT NULL
    memberOrg: one Organization,
    -- SQL: UserId NULL - absent while Invited
    memberUser: lone User,
    -- SQL: Status NOT NULL - see OrgUserStatus in enums.als
    status: one OrgUserStatus,
    -- SQL: Type NOT NULL - see OrgUserRole in enums.als
    role: one OrgUserRole,
    -- SQL: Key VARCHAR(MAX) NULL - present iff status = Confirmed
    key: lone OrgKey
}

/*
Group - SQL table: dbo.Group
A named set of org members used for collection access.
Groups carry no permission flags; permissions come from CollectionGroup.
GroupUser (the junction table) is modeled as the `members` relation.
*/
sig Group {
    -- SQL: OrganizationId NOT NULL
    groupOrg: one Organization,
    -- Derived from junction table: dbo.GroupUser
    members: set OrganizationUser
}

/*
CollectionUser — SQL table: dbo.CollectionUser
A direct collection-access grant for one org member.
This is a data-bearing join table (carries permission flags) and must remain
its own sig so the flags can be quantified over in predicates.
*/
sig CollectionUser {
    -- SQL: CollectionId NOT NULL
    cuCollection: one Collection,
    -- SQL: OrganizationUserId NOT NULL
    cuOrgUser: one OrganizationUser,
    -- SQL: ReadOnly BIT NOT NULL - if Tru member cannot create/edit/delete items
    readOnly: one Bool,
    -- SQL: HidePasswords BIT NOT NULL - if True password fields are hidden
    hidePasswords: one Bool,
    -- SQL: Manage BIT NOT NULL - if True member can rename/delete/assign access
    manage: one Bool
}

/*
CollectionGroup - SQL table: dbo.CollectionGroup
A collection-access grant for all members of a Group.
Same permission flags as CollectionUser.
*/
sig CollectionGroup {
    -- SQL: CollectionId NOT NULL
    cgCollection: one Collection,
    -- SQL: GroupId NOT NULL
    cgGroup: one Group,
    -- SQL: ReadOnly BIT NOT NULL - see CollectionUser
    readOnly: one Bool,
    -- SQL: HidePasswords BIT NOT NULL - see CollectionUser
    hidePasswords: one Bool,
    -- SQL: Manage BIT NOT NULL - see CollectionUser
    manage: one Bool
}
