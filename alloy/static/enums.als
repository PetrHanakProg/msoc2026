/*
enums.als — Abstract signatures for Bitwarden enums

These sigs are hand-written and stable. They correspond to C# enum types in
server/src/Core/AdminConsole/Enums/ and are used throughout predicates.als
to express membership conditions and role checks.

Alloy version: 6
*/

module static/enums


/*
OrgUserStatus — membership lifecycle state
Source: server/src/Core/AdminConsole/Enums/OrganizationUserStatusType.cs

The integer values from C# are documented in comments but are NOT modeled
as Alloy integers as Alloy atoms have no numeric identity. The names are
what matter for predicate logic.
*/

abstract sig OrgUserStatus {}

-- Invited (0): email invite sent; OrganizationUser.UserId is NULL; no vault access
one sig Invited extends OrgUserStatus {}

-- Accepted (1): user clicked the invite link and linked their account
-- UserId is set, but the Key field is still NULL (org key not yet exchanged)
one sig Accepted extends OrgUserStatus {}

-- Confirmed (2): an admin confirmed the member, Key exchanged, full vault access.
-- This is the only status that permits access to org ciphers (SQL: WHERE Status = 2).
one sig Confirmed extends OrgUserStatus {}

-- Revoked (-1): access suspended by an admin, can be restored to prior state.
-- The pre-revocation status is stored in OrganizationUser.StatusNew (not modeled here
-- since we model Revoke as a terminal state for access-control purposes).
one sig Revoked extends OrgUserStatus {}


-- OrgUserRole - role of a member within an organization
-- Source: server/src/Core/AdminConsole/Enums/OrganizationUserType.cs
--
-- Only Owner and Admin are referenced in predicates.als (for the admin bypass).
-- User and Custom are included for completeness and future assertions.

abstract sig OrgUserRole {}

-- Owner (0): full access including billing, acts as admin for access-control purposes
-- Owner + AllowAdminAccessToAllCollectionItems bypasses collection grants.
one sig Owner extends OrgUserRole {}

-- Admin (1): full access excluding billing, same bypass privilege as Owner
-- when AllowAdminAccessToAllCollectionItems is set on the organization
one sig Admin extends OrgUserRole {}

-- Member (2): collection-dependent access; no admin bypass regardless of org settings.
-- Named 'Member' rather than 'User' to avoid a name collision with the 'sig User {}'
one sig Member extends OrgUserRole {}

-- Custom (4):
-- its sub-permissions are not modeled in v1 — Custom is treated like User for
-- cipher access control purposes.
one sig Custom extends OrgUserRole {}
