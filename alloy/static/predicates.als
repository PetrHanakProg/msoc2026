/*
predicates.als - access-control predicates and security assertions

The file encodes the access-control
logic from the UserCipherDetails table-valued function and related C#
layer rules. It must be updated manually if the TVF or service logic changes.

SQL source:
  server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql

C# source (for admin bypass logic):
  server/src/Core/Vault/Authorization/GetCipherPermissionsForUserQuery.cs
  (method CanEditAllCiphersAsync)

A cipher can be in multiple collections; a user may have grants on more than one.
Effective permission = most permissive across all paths

Alloy version: 6
 */

module static/predicates

open static/signatures
open static/facts
open static/enums



-- isConfirmedMember: ou is a confirmed, non-revoked member of a given org.
-- Source: UserCipherDetails CTE: WHERE [Status] = 2
pred isConfirmedMember[ou: OrganizationUser, o: Organization] {
    ou.memberOrg = o
    and ou.status = Confirmed
}


/*
directGrant: a CollectionUser record exists for this (orgUser, collection) pair.
Source: UserCipherDetails LEFT JOIN CollectionUser CU
    ON CU.CollectionId = CC.CollectionId
    AND CU.OrganizationUserId = OU.Id
*/
pred directGrant[ou: OrganizationUser, col: Collection] {
    some cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col
}


/*
groupGrant: the user has a group-based grant for this collection.

CRITICAL: this predicate is only true when NO direct CollectionUser grant
exists for the same (orgUser, collection) pair. This encodes the TVF's
LEFT JOIN guard:
    LEFT JOIN GroupUser GU ON CU.CollectionId IS NULL
                              AND GU.OrganizationUserId = OU.Id
The CU.CollectionId IS NULL condition means: only look up group grants
when the user does NOT have a direct CollectionUser grant for this collection.

If both a direct grant and a group grant exist, the direct grant wins (takes
full precedence).

Source: server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql (JOIN guards)
*/
pred groupGrant[ou: OrganizationUser, col: Collection] {
    -- Precondition: no direct CollectionUser grant for this pair (parenthesised
    -- so the no quantifier does not absorb the and that follows)
    (no cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col)
    -- And there exists a group-based path: ou is in a group that has a CollectionGroup
    and (some g: Group, cg: CollectionGroup |
        ou in g.members          -- ou is a member of group g
        and cg.cgGroup = g       -- group g has a grant on this collection
        and cg.cgCollection = col
    )

}

/*
hasAnyCollectionGrant: ou has at least one grant (direct or group) for any
collection containing cipher c. This is the gateway to org cipher access.

Source: UserCipherDetails WHERE clause:
    CU.CollectionId IS NOT NULL OR CG.CollectionId IS NOT NULL
*/
pred hasAnyCollectionGrant[ou: OrganizationUser, c: Cipher] {
    some col: Collection |
        c in col.ciphers and (directGrant[ou, col] or groupGrant[ou, col])
}



/*
WINNING-ROW HELPERS

These replace the old approach of independently OR-ing a flag across every
collection path. Instead: resolve each grant-holding collection's own
(manage, edit, viewPassword) triple
*/

/*
resolvedManage / resolvedEdit / resolvedViewPassword: the flag value that
wins for a given (ou, col) pair, applying the same CU-then-CG precedence as
the SQL COALESCE.
*/
pred resolvedManage[ou: OrganizationUser, col: Collection] {
    (some cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col and cu.manage = True)
    or (groupGrant[ou, col] and
        some g: Group, cg: CollectionGroup |
            ou in g.members and cg.cgGroup = g and cg.cgCollection = col and cg.manage = True)
}

pred resolvedEdit[ou: OrganizationUser, col: Collection] {
    (some cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col and cu.readOnly = False)
    or (groupGrant[ou, col] and
        some g: Group, cg: CollectionGroup |
            ou in g.members and cg.cgGroup = g and cg.cgCollection = col and cg.readOnly = False)
}

pred resolvedViewPassword[ou: OrganizationUser, col: Collection] {
    (some cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col and cu.hidePasswords = False)
    or (groupGrant[ou, col] and
        some g: Group, cg: CollectionGroup |
            ou in g.members and cg.cgGroup = g and cg.cgCollection = col and cg.hidePasswords = False)
}

/*
isGrantHoldingCollection: col is a candidate row for the winning-row
selection - it contains c, and ou has some grant (direct or group) on it.
Same gate as hasAnyCollectionGrant's inner existential, factored out so the
tie-break predicates below can quantify over "all of ou's candidate
collections for c" directly.
*/
pred isGrantHoldingCollection[ou: OrganizationUser, c: Cipher, col: Collection] {
    c in col.ciphers and (directGrant[ou, col] or groupGrant[ou, col])
}

/*
collectionBeats: colA is STRICTLY preferred over colB under the real
tie-break order (Manage desc, then Edit desc, then ViewPassword desc).
*/
pred collectionBeats[ou: OrganizationUser, colA, colB: Collection] {
    (resolvedManage[ou, colA] and not resolvedManage[ou, colB])
    or (
        (resolvedManage[ou, colA] iff resolvedManage[ou, colB])
        and resolvedEdit[ou, colA] and not resolvedEdit[ou, colB]
    )
    or (
        (resolvedManage[ou, colA] iff resolvedManage[ou, colB])
        and (resolvedEdit[ou, colA] iff resolvedEdit[ou, colB])
        and resolvedViewPassword[ou, colA] and not resolvedViewPassword[ou, colB]
    )
}

/*
winningCollection: col is a maximal element among ou's grant-holding
collections for c under collectionBeats
beats it. Deliberately not the unique winner: if two collections tie
exactly (identical resolved triples), neither beats the other, so both
satisfy this predicate - but since a tie means IDENTICAL flag values,
picking either one via some col: winningCollection[...] in the permission
predicates below yields the same answer.
LINQ tie picks an arbitrary-but-equally-correct row.
*/
pred winningCollection[ou: OrganizationUser, c: Cipher, col: Collection] {
    isGrantHoldingCollection[ou, c, col]
    and (no col2: Collection |
        isGrantHoldingCollection[ou, c, col2] and collectionBeats[ou, col2, col])
}


/*
canSee: user u can see (read) cipher c.
This is the visibility predicate

Three paths to visibility (corresponding to the TVF's two SELECT branches
plus the C# admin bypass):

1. Personal cipher: u directly owns c (c.owner = u)
   Source: UserCipherDetails UNION ALL branch:
       SELECT *, 1 [Edit], 1 [ViewPassword], 1 [Manage], 0 [OrganizationUseTotp]
       FROM CipherDetails(@UserId) WHERE UserId = @UserId

2. Org cipher via collection grants: u is a confirmed member of an enabled org
   that owns c, and has at least one collection grant.
   Source: UserCipherDetails main SELECT with INNER JOIN on CTE + Organization.

3. Admin bypass: u is an Owner or Admin in an org with the bypass flag set.
   In this case u can see ALL org ciphers regardless of collection assignment.
   Source: GetCipherPermissionsForUserQuery.cs::CanEditAllCiphersAsync
   This bypass is checked in C# layel, NOT in SQL. The flag
   AllowAdminAccessToAllCollectionItems IS in the Organization SQL table, but
   the bypass logic is applied by the application before calling the TVF
*/
pred canSee[u: User, c: Cipher] {
    -- Path 1: personal cipher - user is the direct owner
    c.owner = u

    -- Path 2: org cipher via collection grants
    or (
        c.owner in Organization
        and (some ou: OrganizationUser |
            isConfirmedMember[ou, c.owner & Organization]       -- confirmed in this org
            and ou.memberUser = u                                 -- this user's membership record
            and (c.owner & Organization).enabled = True  -- org must be enabled
            and hasAnyCollectionGrant[ou, c]     -- has at least one collection grant
        )
    )

    -- Path 3: admin bypass (Owner or Admin + AllowAdminAccessToAllCollectionItems)
    -- This bypass is applied in C# (GetCipherPermissionsForUserQuery.cs) Before calling the TVF
    or (
        c.owner in Organization
        and (some ou: OrganizationUser |
            isConfirmedMember[ou, c.owner & Organization]
            and ou.memberUser = u
            and (c.owner & Organization).enabled = True
            and (c.owner & Organization).allowAdminAccess = True
            and ou.role in (Owner + Admin)
        )
    )
}


/*
canEdit: user u can create, edit, or delete ciphers in collections where c appears.
Edit = the winning collection's own resolved edit value (see winningCollection)

CORRECTED: this used to OR readOnly=False independently across every collection
path ("MAX semantics"). Real semantics: exactly one collection's row wins the
Manage/Edit/ViewPassword tie-break (CipherRepository.cs), and Edit is read off
THAT row alone

For personal ciphers: always editable (owner has full access) - untouched, this
path never goes through the winning-row selection in the real code either.
For org ciphers via admin bypass: always editable - also untouched, same reason.
For org ciphers via collection grants: editable iff the WINNING collection's
resolved Edit is true.


Source: UserCipherDetails:
    CASE WHEN COALESCE(CU.[ReadOnly], CG.[ReadOnly], 0) = 0 THEN 1 ELSE 0 END [Edit]
(per-collection resolution, unchanged) selected by CipherRepository.cs's
OrderByDescending(Manage).ThenByDescending(Edit).ThenByDescending(ViewPassword).First()
(the winning-row selection, newly modeled here via winningCollection).
*/
pred canEdit[u: User, c: Cipher] {
    -- Personal cipher: owner always has edit access
    c.owner = u

    -- Org cipher via admin bypass: admins can always edit
    or (
        c.owner in Organization
        and (some ou: OrganizationUser |
            isConfirmedMember[ou, c.owner & Organization]
            and ou.memberUser = u
            and (c.owner & Organization).enabled = True
            and (c.owner & Organization).allowAdminAccess = True
            and ou.role in (Owner + Admin)
        )
    )

    -- Org cipher via collection grants: Edit comes from the One winning row
    or (
        c.owner in Organization
        and (some ou: OrganizationUser, col: Collection |
            winningRow[u, c, ou, col]
            and resolvedEdit[ou, col]
        )
    )
}


/*
canViewPassword: user u can see the password of cipher c.
ViewPassword = the winning collection's own resolvedViewPassword value.


CORRECTED: same winning-row fix as canEdit, applied to the hidePasswords flag.


Source: UserCipherDetails:
    CASE WHEN COALESCE(CU.[HidePasswords], CG.[HidePasswords], 0) = 0
         THEN 1 ELSE 0 END [ViewPassword]
*/

pred canViewPassword[u: User, c: Cipher] {
    -- Personal cipher: owner can always view password
    c.owner = u

    -- Org cipher via admin bypass: admins can always view passwords
    or (
        c.owner in Organization
        and (some ou: OrganizationUser |
            isConfirmedMember[ou, c.owner & Organization]
            and ou.memberUser = u
            and (c.owner & Organization).enabled = True
            and (c.owner & Organization).allowAdminAccess = True
            and ou.role in (Owner + Admin)
        )
    )

    -- Org cipher via collection grants: ViewPassword comes from the ONE winning
    or (
        c.owner in Organization
        and (some ou: OrganizationUser, col: Collection |
            winningRow[u, c, ou, col]
            and resolvedViewPassword[ou, col]
        )
    )
}


/*
canManage: user u can manage the collection(s) that contain cipher c.
Manage = the winning collection's own resolvedManage value

Managing a collection means: renaming it, deleting it, and assigning/removing
access grants for other members. canManage implies full edit access in practice,
but is modeled as a separate flag here (matching the SQL schema).

Source: UserCipherDetails:
    CASE WHEN COALESCE(CU.[Manage], CG.[Manage], 0) = 1 THEN 1 ELSE 0 END [Manage]
*/
pred canManage[u: User, c: Cipher] {
    -- Personal cipher: owner always has manage access
    c.owner = u

    -- Org cipher via admin bypass: admins can always manage
    or (
        c.owner in Organization
        and (some ou: OrganizationUser |
            isConfirmedMember[ou, c.owner & Organization]
            and ou.memberUser = u
            and (c.owner & Organization).enabled = True
            and (c.owner & Organization).allowAdminAccess = True
            and ou.role in (Owner + Admin)
        )
    )

    -- Org cipher via collection grants
    or (
        c.owner in Organization
        and (some ou: OrganizationUser, col: Collection |
            winningRow[u, c, ou, col]
            and resolvedManage[ou, col]
        )
    )
}

/*
isCandidateRow: (ou, col) is a genuine candidate row for user u's access to
cipher c -- ou is one of (possibly several) confirmed OrganizationUser
records linking u to c's owning org, and col is ou's own locally-winning
collection under winningCollection (unchanged, reused as-is).

facts.als deliberately does not forbid two OrganizationUser
records for the same (User, Organization) pair
*/

pred isCandidateRow[u: User, c: Cipher, ou: OrganizationUser, col: Collection] {
    c.owner in Organization
    and isConfirmedMember[ou, c.owner & Organization]
    and ou.memberUser = u
    and (c.owner & Organization).enabled = True
    and winningCollection[ou, c, col]
}

/*
rowBeats: row (ouA, colA) is STRICTLY preferred over row (ouB, colB) under
the real tie-break order (Manage desc, Edit desc, ViewPassword desc)
*/
pred rowBeats[ouA: OrganizationUser, colA: Collection, ouB: OrganizationUser, colB: Collection] {
    (resolvedManage[ouA, colA] and not resolvedManage[ouB, colB])
    or (
        (resolvedManage[ouA, colA] iff resolvedManage[ouB, colB])
        and resolvedEdit[ouA, colA] and not resolvedEdit[ouB, colB]
    )
    or (
        (resolvedManage[ouA, colA] iff resolvedManage[ouB, colB])
        and (resolvedEdit[ouA, colA] iff resolvedEdit[ouB, colB])
        and resolvedViewPassword[ouA, colA] and not resolvedViewPassword[ouB, colB]
    )
}

/*
winningRow: (ou, col) is THE single winning row for user u's access to
cipher c across all candidate rows
*/
pred winningRow[u: User, c: Cipher, ou: OrganizationUser, col: Collection] {
    isCandidateRow[u, c, ou, col]
    and (no ou2: OrganizationUser, col2: Collection |
        isCandidateRow[u, c, ou2, col2] and rowBeats[ou2, col2, ou, col])
}


/*
ASSERTIONS
Each assertion is a security property
Expect: no counterexample found for all assertions.
*/


/*
RevokedCannotSee: a revoked member cannot see any org cipher.

Security property: revoking a member immediately removes their vault access.

Source: UserCipherDetails CTE WHERE [Status] = 2
*/
assert RevokedCannotSee {
    all u: User, c: Cipher |
        c.owner in Organization and
        (some ou: OrganizationUser |
            ou.memberUser = u
            and ou.memberOrg = c.owner
            and ou.status = Revoked)
        implies not canSee[u, c]
}


/*
DisabledOrgBlocksAccess: when an org is disabled, none of its ciphers are visible.

Security property: disabling an organization is a kill switch that immediately
blocks all member access

Source: UserCipherDetails INNER JOIN Organization O ON O.Enabled = 1
*/

assert DisabledOrgBlocksAccess {
    all o: Organization | o.enabled = False implies
        no u: User, c: Cipher | c.owner = o and canSee[u, c]
}


/*
UncollectedCipherInvisible: org ciphers in no collection are invisible to regular users.

Security property: a cipher that has not been assigned to any collection is not
accessible to regular members, since they have no collection
grant to it. The admin bypass is the only exception, Owner/Admin members with
AllowAdminAccessToAllCollectionItems=true can see ciphers.

The assertion is scoped to the non-bypass case to remain a clean

Source: UserCipherDetails WHERE CU.CollectionId IS NOT NULL OR CG.CollectionId IS NOT NULL
*/
assert UncollectedCipherInvisible {
    all c: Cipher |
        c.owner in Organization
        and (no col: Collection | c in col.ciphers)  -- cipher is in no collection
        implies
        -- No user can see it unless they have admin bypass
        no u: User | canSee[u, c] and not (
            some ou: OrganizationUser |
                ou.memberUser = u
                and isConfirmedMember[ou, c.owner & Organization]
                and (c.owner & Organization).allowAdminAccess = True
                and ou.role in (Owner + Admin)
        )
}


/*
PersonalCipherIsPrivate: a personal cipher is invisible to all other users.

Security property: personal vault items are strictly private. No other user
can access them regardless of organization membership or admin privileges.

Source: UserCipherDetails UNION ALL branch WHERE UserId = @UserId
*/
assert PersonalCipherIsPrivate {
    all c: Cipher, u, v: User |
        c.owner = u and u != v implies not canSee[v, c]
}


/*
ReadOnlyPreventsEdit: if ALL collection grants for a user on a cipher are ReadOnly,
then canEdit must be false.

Security property: ReadOnly grants cannot be circumvented through the normal
collection-grant path. A user can only edit if at least one collection path
(direct or group) grants write access.

this assertion does NOT apply when the admin bypass is active (admin bypass
always grants Edit) The assertion is scoped to the non-bypass case.
*/
assert ReadOnlyPreventsEdit {
    all u: User, c: Cipher |
        c.owner in Organization
        and (some ou: OrganizationUser |
            ou.memberUser = u and isConfirmedMember[ou, c.owner & Organization])
        -- No admin bypass active for this user
        and not (some ou: OrganizationUser |
            ou.memberUser = u
            and isConfirmedMember[ou, c.owner & Organization]
            and (c.owner & Organization).allowAdminAccess = True
            and ou.role in (Owner + Admin))
        -- All direct grants for this user on this cipher are ReadOnly
        and (all col: Collection, cu: CollectionUser |
            c in col.ciphers and cu.cuOrgUser.memberUser = u and cu.cuCollection = col
            implies cu.readOnly = True)
        -- All group grants for this user on this cipher are ReadOnly
        and (all col: Collection, g: Group, cg: CollectionGroup |
            c in col.ciphers and cg.cgCollection = col and cg.cgGroup = g
            and (some ou: OrganizationUser |
                ou.memberUser = u and ou in g.members and isConfirmedMember[ou, c.owner & Organization])
            implies cg.readOnly = True)
        implies not canEdit[u, c]
}

/*
NoAccessWithoutGrant: a confirmed, non-bypass member with no direct or group
grant on ANY collection containing a cipher cannot see that cipher, provided
the cipher belongs to at least one collection at all.
*/
assert NoAccessWithoutGrant {
    all u: User, c: Cipher |
        c.owner in Organization
        and (some col: Collection | c in col.ciphers)
        and (c.owner & Organization).enabled = True
        and (c.owner & Organization).allowAdminAccess = False
        and (all ou: OrganizationUser |
            ou.memberUser = u and ou.memberOrg = (c.owner & Organization)
            implies
            (no col: Collection, cu: CollectionUser |
                c in col.ciphers and cu.cuOrgUser = ou and cu.cuCollection = col)
            and
            (no col: Collection, g: Group, cg: CollectionGroup |
                c in col.ciphers and ou in g.members
                and cg.cgGroup = g and cg.cgCollection = col))
        implies not canSee[u, c]
}

-- RUN COMMANDS - for non-vacuity verification
-- the model must produce instances (not be empty).

-- At least one (user, cipher) pair where access holds through a direct collection grant.
run canSeeExists {
/*
    Require a direct CollectionUser grant from the user's OU to the cipher's collection,
    and explicitly exclude admin bypass.
*/
    some u: User, c: Cipher, ou: OrganizationUser, col: Collection, cu: CollectionUser |
        canSee[u, c]
        and c in col.ciphers
        and cu.cuOrgUser = ou and cu.cuCollection = col
        and ou.memberUser = u
        and isConfirmedMember[ou, c.owner & Organization]
        and (c.owner & Organization).allowAdminAccess = False  -- no admin bypass
} for 4


-- The read-only path must be reachable (a user can see but not edit via ReadOnly=True collection grant)

run ReadOnlyPathExists {
    -- Require explicit direct CollectionUser grant with readOnly=True so the solver cannot satisfy
    -- canSee via admin-bypass or personal-ownership, and the derivation rule finds the right cipher.
    some u: User, c: Cipher, ou: OrganizationUser, col: Collection, cu: CollectionUser |
        canSee[u, c] and not canEdit[u, c]
        and c in col.ciphers
        and cu.cuOrgUser = ou and cu.cuCollection = col and cu.readOnly = True
        and cu.cuOrgUser = ou and cu.cuCollection = col and cu.readOnly = True
        and ou.memberUser = u and isConfirmedMember[ou, c.owner & Organization]
} for 4


-- The hidePasswords path must be reachable (a user can see but not view password via HidePasswords=True)

run HidePasswordsPathExists {
    -- Require explicit direct CollectionUser grant with hidePasswords=True.
    some u: User, c: Cipher, ou: OrganizationUser, col: Collection, cu: CollectionUser |
        canSee[u, c] and not canViewPassword[u, c]
        and c in col.ciphers
        and cu.cuOrgUser = ou and cu.cuCollection = col and cu.hidePasswords = True
        and ou.memberUser = u and isConfirmedMember[ou, c.owner & Organization]
} for 4



-- A user can manage a collection-assigned cipher through an explicit Manage=True direct grant.

run ManagePathExists {
    -- Require cipher in a collection so find_cipher_in_collection derivation succeeds.
    -- Without this, the solver may find admin-level canManage without any collection.
    some u: User, c: Cipher, ou: OrganizationUser, col: Collection, cu: CollectionUser |
        canManage[u, c]
        and c in col.ciphers
        and c.owner in Organization
        and cu.cuOrgUser = ou and cu.cuCollection = col
        and cu.manage = True
        and ou.memberUser = u
        and isConfirmedMember[ou, c.owner & Organization]
        and (c.owner & Organization).allowAdminAccess = False  -- no admin bypass
} for 4


/*
Group grant fires when there is no direct CollectionUser grant for this (orgUser, collection).
Source: TVF LEFT JOIN GroupUser GU ON CU.CollectionId IS NULL, the null-guard condition.

Constraints explicitly so that there is no `canSee` bypass 
through admin
*/
run GroupGrantOnlyExists {
    some u: User, c: Cipher, ou: OrganizationUser, col: Collection, g: Group, cg: CollectionGroup |
        c in col.ciphers
        and c.owner in Organization
        and (c.owner & Organization).enabled = True
        and (c.owner & Organization).allowAdminAccess = False
        and ou.memberUser = u
        and isConfirmedMember[ou, c.owner & Organization]
        and (no cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col)
        and ou in g.members
        and cg.cgGroup = g
        and cg.cgCollection = col
        and cg.readOnly = False
} for 5 but 1 Cipher, 1 Collection

/*
Direct grant takes full precedence over group grant on the same collection.
A CollectionUser row (ReadOnly=True) coexists with a CollectionGroup row (ReadOnly=False).
The user cannot edit because the TVF's null-guard skips the group grant when a direct grant
exists: LEFT JOIN GroupUser GU ON CU.CollectionId IS NULL.
*/
run DirectGrantPrecedesGroupGrant {
    some u: User, c: Cipher, col: Collection, ou: OrganizationUser |
        canSee[u, c] and not canEdit[u, c]
        and c in col.ciphers
        and ou.memberUser = u
        and isConfirmedMember[ou, c.owner & Organization]
        and directGrant[ou, col]
        and (some g: Group, cg: CollectionGroup |
            ou in g.members and cg.cgGroup = g
            and cg.cgCollection = col and cg.readOnly = False)
} for 5 but 2 Organization, 2 Cipher, 2 Collection

/*
Assertion-scenario run commands
Each run below produces an instance that exercises an assert boundary case,
allowing the pipeline to generate a C# integration test for that scenario.
*/

/*
RevokedCannotSee scenario: revoked member has a collection grant but
TVF status-gate blocks access (Status != Confirmed in the TVF WHERE clause).
*/
run RevokedMemberScenario {
    some u: User, c: Cipher, ou: OrganizationUser, col: Collection |
        c in col.ciphers and c.owner in Organization
        and ou.memberUser = u and ou.memberOrg = (c.owner & Organization)
        and ou.status = Revoked
        and (some cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col)
} for 4

/*
DisabledOrgBlocksAccess scenario: confirmed member has a collection grant
but the owning org has enabled = False, which the TVF uses to gate access.
*/
run DisabledOrgScenario {
    some u: User, c: Cipher, ou: OrganizationUser, col: Collection |
        c in col.ciphers and c.owner in Organization
        and ou.memberUser = u and ou.memberOrg = (c.owner & Organization)
        and ou.status = Confirmed
        and (c.owner & Organization).enabled = False
        and (some cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col)
} for 4

/*
UncollectedCipherInvisible scenario: regular member (Member or Custom role)
exists in the org but the cipher belongs to no collection, so there is no
grant row for the TVF to find, cipher is invisible.
*/
run UncollectedCipherScenario {
    some u: User, c: Cipher, ou: OrganizationUser |
        c.owner in Organization
        and ou.memberUser = u and ou.memberOrg = (c.owner & Organization)
        and ou.status = Confirmed and ou.role in (Member + Custom)
        and no col: Collection | c in col.ciphers
} for 4

/*
NoAccessWithoutGrant scenario: confirmed, non-bypass member exists in the org,
the cipher IS in a collection (unlike UncollectedCipherScenario above), but the
member has no direct or group grant on any collection containing it.
*/
run NoAccessWithoutGrantScenario {
    some u: User, c: Cipher, ou: OrganizationUser |
        c.owner in Organization
        and (some col: Collection | c in col.ciphers)
        and ou.memberUser = u and ou.memberOrg = (c.owner & Organization)
        and ou.status = Confirmed
        and (c.owner & Organization).enabled = True
        and (c.owner & Organization).allowAdminAccess = False
        and (all ou2: OrganizationUser |
            ou2.memberUser = u and ou2.memberOrg = (c.owner & Organization)
            implies
            (no col: Collection, cu: CollectionUser |
                c in col.ciphers and cu.cuOrgUser = ou2 and cu.cuCollection = col)
            and
            (no col: Collection, g: Group, cg: CollectionGroup |
                c in col.ciphers and ou2 in g.members
                and cg.cgGroup = g and cg.cgCollection = col))
} for 4

/*
PersonalCipherIsPrivate scenario: u1 owns the cipher personally, u2 is a
distinct user. The TVF returns only ciphers the requesting user owns or has
an org grant for u2 has neither, so u2 cannot see u1's cipher.
*/
run PersonalPrivacyScenario {
    some u1, u2: User, c: Cipher | c.owner = u1 and u1 != u2
} for 4

/*
WinningRowDivergenceExists: witnesses the corrected winning-row semantics

Pins one confirmed, non-bypass org member with DIRECT CollectionUser grants
on two DIFFERENT collections (colA, colB) containing the same cipher c:
  colA: Manage=False, ReadOnly=False (Edit=True),  HidePasswords=True  (ViewPassword=False)
  colB: Manage=False, ReadOnly=True  (Edit=False), HidePasswords=False (ViewPassword=True)

Both tie on Manage=False; the tie-break falls to Edit, where colA wins
(Edit=True beats Edit=False) -- so the real, corrected winning row is colA:
Edit=True, ViewPassword=False. The OLD independent-OR model this file used to
encode would have said Edit = (True OR False) = true (agrees with corrected)
AND ViewPassword = (False OR True) = true (DISAGREES -- old model wrongly
said true; corrected model correctly says false). Hand-derivation confirmed
against winningCollection/resolvedEdit/resolvedViewPassword's actual Alloy
encoding before trusting this run command, not just against the prose above.
*/
run WinningRowDivergenceExists {
    some u: User, c: Cipher, ou: OrganizationUser, colA, colB: Collection, cuA, cuB: CollectionUser |
        c.owner in Organization
        and (c.owner & Organization).enabled = True
        and (c.owner & Organization).allowAdminAccess = False
        and ou.memberUser = u
        and isConfirmedMember[ou, c.owner & Organization]
        and c in colA.ciphers and c in colB.ciphers
        and colA != colB
        and cuA.cuOrgUser = ou and cuA.cuCollection = colA
        and cuA.manage = False and cuA.readOnly = False and cuA.hidePasswords = True
        and cuB.cuOrgUser = ou and cuB.cuCollection = colB
        and cuB.manage = False and cuB.readOnly = True and cuB.hidePasswords = False
        and canEdit[u, c] and not canViewPassword[u, c]
} for 5 but 1 Cipher, 2 Collection

/*
MATERIALIZED FLAGS - forcing the solver to compute
the expected outcome of every fixture

scripts/alloy_test_expectations.yaml used to have an expected
block per run command saying what canSee/canEdit/canViewPassword/canManage
should evaluate to for the scenario and typed
it in, entirely independent of these predicates. Nothing cross-checked that
guess against what the model actually says. This fact closes that gap: it
binds each User field declared in signatures.als to the corresponding
predicate via iff, so any satisfying instance the solver finds must carry
the correct, model-computed answer as part of the instance itself.
scripts/instance_to_fixture.py reads it directly from the parsed XML
instead of a YAML entry.

This is not a new constraint on the modeled
*/

fact MaterializedFlags {
    all u: User, c: Cipher | c in u.canSeeRel iff canSee[u, c]
    all u: User, c: Cipher | c in u.canEditRel iff canEdit[u, c]
    all u: User, c: Cipher | c in u.canViewPasswordRel iff canViewPassword[u, c]
    all u: User, c: Cipher | c in u.canManageRel iff canManage[u, c]
}

