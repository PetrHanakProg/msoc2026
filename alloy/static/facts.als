/*
facts.als - structural invariants derived from the SQL schema

Hand-written. These facts encode SQL constraints
as Alloy facts that keep the model from admitting
database states that could never exist in production.
*/

module static/facts

open static/signatures
open static/enums


/*
-- Cipher.owner is User XOR Organization (never both, never neither).
-- Source: dbo.Cipher
*/
fact CipherOwnerIsExclusive {
    all c: Cipher |
        (c.owner in User and c.owner not in Organization)
        or
        (c.owner in Organization and c.owner not in User)
}

-- Org ciphers in a collection must belong to the same org as the collection.
-- Source: dbo.CollectionCipher FK + dbo.Collection.OrganizationId NOT NULL.
fact CipherInCollectionSameOrg {
    all col: Collection, c: Cipher |
        c in col.ciphers implies (c.owner in Organization implies col.org = c.owner)
}

-- Personal ciphers (owned by a User) cannot appear in any collection.
-- Source: dbo.CollectionCipher is only populated for org ciphers.
fact PersonalCiphersNotInCollections {
    all c: Cipher |
        c.owner in User implies no col: Collection | c in col.ciphers
}

-- UserId (memberUser) is absent iff status = Invited.
-- Source: dbo.OrganizationUser UserId NULL
fact OrgUserInvitedHasNoUser {
    all ou: OrganizationUser |
        (ou.status = Invited) iff (no ou.memberUser)
}

-- Key is present iff status = Confirmed (key exchange happens at Confirm time).
-- Source: dbo.OrganizationUser Key VARCHAR(MAX) NULL
fact OrgUserConfirmedHasKey {
    all ou: OrganizationUser |
        (ou.status = Confirmed) iff (some ou.key)
}


-- Members of a Group must be in the same org as the Group.
-- Source: dbo.GroupUser — GroupId FK + OrganizationUserId FK both resolve to the same org.
fact GroupMembersSameOrg {
    all g: Group, member: OrganizationUser |
        member in g.members implies member.memberOrg = g.groupOrg
}

-- CollectionUser grants are scoped: collection.org must equal orgUser.memberOrg.
-- Source: dbo.CollectionUser FKs - CollectionId and OrganizationUserId share an org.
fact CollectionUserSameOrg {
    all cu: CollectionUser | cu.cuCollection.org = cu.cuOrgUser.memberOrg
}

-- CollectionGroup grants are scoped: collection.org must equal group.groupOrg.
-- Source: dbo.CollectionGroup FKs - CollectionId and GroupId share an org.
fact CollectionGroupSameOrg {
    all cg: CollectionGroup | cg.cgCollection.org = cg.cgGroup.groupOrg
}


-- CollectionUser: composite pk  (CollectionId, OrganizationUserId).
-- No two CollectionUser rows can grant access to the same (collection, orgUser) pair.
fact CollectionUserUniquePair {
    all disj cu1, cu2: CollectionUser |
        not (cu1.cuCollection = cu2.cuCollection and cu1.cuOrgUser = cu2.cuOrgUser)
}

-- CollectionGroup: composite PK (CollectionId, GroupId).
fact CollectionGroupUniquePair {
    all disj cg1, cg2: CollectionGroup |
        not (cg1.cgCollection = cg2.cgCollection and cg1.cgGroup = cg2.cgGroup)
}

-- OrgKey atoms are not shared across OrganizationUser records.
-- Each confirmed member holds an independently encrypted copy of the org key.
fact OrgKeyUnique {
    all disj ou1, ou2: OrganizationUser |
        (some ou1.key and some ou2.key) implies ou1.key != ou2.key
}
