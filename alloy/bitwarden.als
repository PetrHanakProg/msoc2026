/*
This file contains only module imports.

Module structure (all files are hand-written):
  static/enums.als - abstract sigs: OrgUserStatus, OrgUserRole, Bool
  static/signatures.als - sig declarations for all modeled SQL tables
  static/facts.als - structural invariants from SQL constraints
  static/predicates.als - canSee, canEdit, canManage, canViewPassword, all assertions

What is modeled:
  The access-control rules that determine which users can see, edit, view passwords
  in, or manage which vault items (Ciphers). The model is scoped to access control
  only; billing, event logging, key material, and token issuance are excluded.

What is NOT modeled (out of scope for v1):
  - Soft-delete (DeletedDate): a display filter, not an access gate
  - Provider-admin elevation: a third membership layer with no SQL representation
  - DefaultUserCollection (CollectionType=1): semantics still settling
  - LimitItemDeletion org flag: a deletion policy, not a visibility gate

Source:
  SQL schema:  server/src/Sql/dbo/ (tables, views, stored procedures, TVFs)
  C# enums:    server/src/Core/AdminConsole/Enums/

Alloy version: 6

To verify all assertions at scope 4, run in the Alloy Analyzer:
check RevokedCannotSee for 4
check DisabledOrgBlocksAccess for 4
check UncollectedCipherInvisible for 4
check PersonalCipherIsPrivate for 4
check ReadOnlyPreventsEdit for 4
check NoAccessWithoutGrant for 4

Model is not empty, run:
run canSeeExists for 3 but 2 Organization, 3 Cipher, 2 Collection
*/

module bitwarden

open static/enums
open static/signatures
open static/facts
open static/predicates
