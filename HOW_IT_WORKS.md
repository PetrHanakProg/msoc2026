# How this project works

A complete description of what this repository does and how it does it.
It covers the current state of the project.
Every stage of the pipeline comes with an example of what that
stage produces, taken from the files committed in this repository.


## 1. The one-paragraph summary

Bitwarden is a password manager. Its server decides, for every vault item and every
user, whether that user can **see** the item, **edit** it, **view its password**, and
**manage** it. This project writes those rules down as a formal model in
the **Alloy** specification language. It then uses Alloy's solver to invent concrete
example situations ("a user in two collections with these grants..."), and turns each
one automatically into a C# integration test that runs against Bitwarden's
database code. Finally, a **mutation-testing harness** plants bugs in
the real code and in the model, one at a time, and records which checks notice each
bug: the model's formal assertions, the generated tests, or a hand-written test
suite. The result is a measurement of how much bug-catching power each layer has.



## 2. Background

A few Bitwarden concepts:

Concept - What it is 
**Cipher** - One vault item (a login, card, not...). It is owned **either** by one user (a *personal* cipher) **or** by one organization (an *org* cipher). Never both.
**User** - A person with an account.
**Organization** - A shared space, e.g. a company. It has two flags that matter here: **Enabled** (a kill switch: when it is false, nobody sees the org's items) and **AllowAdminAccessToAllCollectionItems** (lets owners and admins see everything).
**OrganizationUser** - A user's *membership* in an organization. It has a **status** (`Invited`, `Accepted`, `Confirmed`, `Revoked`) and a **role** (`Owner`, `Admin`, `User`, `Custom`). Only `Confirmed` members get access.
**Collection** - A folder-like grouping of org ciphers. A cipher can be in several collections, or in none.
**CollectionUser** - A *direct grant*: "this membership may access this collection", with three flags: `ReadOnly`, `HidePasswords`, `Manage`.
**Group** / **GroupUser** - A named set of memberships.
**CollectionGroup** - A *group grant*: "members of this group may access this collection", with the same three flags.

The four permission answers the server computes for a (user, cipher) pair:

- **Can see**: the item shows up in the user's vault at all.
- **Can edit**: true unless the winning grant is `ReadOnly`.
- **Can view password**: true unless the winning grant has `HidePasswords`.
- **Can manage**: true only if the winning grant has `Manage`.

Personal ciphers are simple: the owner gets all four and nobody else gets anything.
The interesting logic is all about org ciphers.



## 3. The system under test: Bitwarden's access-control code

`server/` is a local checkout of the Bitwarden server. It is its own git repository and
is **not** tracked by this project's git. The model is built from three pieces of
real code in it.

### 3.1 The SQL function `UserCipherDetails`

`server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql` is a table-valued function:
given a user id, it returns every cipher that user can see, with their
permission flags. On SQL Server, `GetManyByUserIdAsync` reaches it through the stored
procedure `CipherDetails_ReadByUserId`, which is just `SELECT * FROM
UserCipherDetails(@UserId)`.

```
WITH [CTE] AS (                                   -- the user's memberships...
    SELECT [Id], [OrganizationId] FROM [OrganizationUser]
    WHERE [UserId] = @UserId AND [Status] = 2     -- ...Confirmed ones only (Revoked = -1 is dropped)
)
SELECT C.*,
    CASE WHEN COALESCE(CU.[ReadOnly],      CG.[ReadOnly],      0) = 0 THEN 1 ELSE 0 END [Edit],
    CASE WHEN COALESCE(CU.[HidePasswords], CG.[HidePasswords], 0) = 0 THEN 1 ELSE 0 END [ViewPassword],
    CASE WHEN COALESCE(CU.[Manage],        CG.[Manage],        0) = 1 THEN 1 ELSE 0 END [Manage],
    ...
FROM [dbo].[CipherDetails](@UserId) C
INNER JOIN [CTE] OU ON C.[UserId] IS NULL AND C.[OrganizationId] IN (SELECT [OrganizationId] FROM [CTE])
INNER JOIN [dbo].[Organization] O ON ... AND O.[Enabled] = 1          -- org kill switch
LEFT JOIN [dbo].[CollectionCipher] CC ON CC.[CipherId] = C.[Id]
LEFT JOIN [dbo].[CollectionUser]   CU ON CU.[CollectionId] = CC.[CollectionId] AND CU.[OrganizationUserId] = OU.[Id]
LEFT JOIN [dbo].[GroupUser]        GU ON CU.[CollectionId] IS NULL      -- group path ONLY if no direct grant
                                     AND GU.[OrganizationUserId] = OU.[Id]
LEFT JOIN [dbo].[Group]            G  ON G.[Id] = GU.[GroupId]
LEFT JOIN [dbo].[CollectionGroup]  CG ON CG.[CollectionId] = CC.[CollectionId] AND CG.[GroupId] = GU.[GroupId]
WHERE CU.[CollectionId] IS NOT NULL OR CG.[CollectionId] IS NOT NULL    -- must have SOME grant

UNION ALL                                         -- personal ciphers: owner gets everything
SELECT *, 1 [Edit], 1 [ViewPassword], 1 [Manage], 0 [OrganizationUseTotp]
FROM [dbo].[CipherDetails](@UserId) WHERE [UserId] = @UserId;
```

These are the rules this encodes. The model reproduces every one of them.

1. **Status gate.** Only `Confirmed` memberships count.
2. **Kill switch.** A disabled organization shows nothing.
3. **Grant required.** An org cipher is returned only through at least one direct or
   group grant on a collection that contains it.
4. **Direct beats group.** `CU.CollectionId IS NULL` means group grants are considered
   only when there is no direct grant for that membership and collection. Then
   `COALESCE(CU.x, CG.x, 0)` reads the direct grant's flag first. So a restrictive
   direct grant cannot be upgraded by a generous group grant.
5. **One row per path.** The function does **no aggregation**. A user who reaches the
   same cipher through two collections gets two rows, each with its own flags.

### 3.2 The "winning row" in the C# repository

The C# method that calls the function collapses those multiple rows into one answer.
From `server/src/Infrastructure.Dapper/Vault/Repositories/CipherRepository.cs`,
`GetManyByUserIdAsync`:

```csharp
return results
    .GroupBy(c => c.Id)
    .Select(g =>
        g.OrderByDescending(og => og.Manage)
            .ThenByDescending(og => og.Edit)
            .ThenByDescending(og => og.ViewPassword).First())
    .ToList();
```

So the final answer is one whole winning row, chosen by comparing `Manage`, then
`Edit`, then `ViewPassword`. It is not an independent OR for
each flag. The difference is observable.

- Row A has Edit = 1 and ViewPassword = 0.
- Row B has Edit = 0 and ViewPassword = 1.
- The user gets Row A: Edit = true, ViewPassword = **false**.
- An OR-per-flag rule would wrongly say both are true.

The Entity Framework repository (used for SQLite, MySQL and Postgres) applies the
same ordering.

### 3.3 The LINQ port

`server/src/Infrastructure.EntityFramework/Repositories/Queries/UserCipherDetailsQuery.cs`
reimplements the SQL function in LINQ for the non-SQL-Server databases. It uses the
same joins, the same "group path only if `cu` is null" guard, and flags computed as
e.g. `Edit = cu == null ? (cg != null && cg.ReadOnly == false) : cu.ReadOnly == false`.

### 3.4 The admin bypass, which lives elsewhere

Owners and Admins of an organization with `AllowAdminAccessToAllCollectionItems = true`
can access everything. This is **not** in the SQL. It is applied in
`server/src/Core/Vault/Queries/GetCipherPermissionsForUserQuery.cs`
(`CanEditAllCiphersAsync`). The model includes it so the formal properties cover the
whole surface. However, neither test suite can exercise it, because both call
`GetManyByUserIdAsync` directly.



## 4. The pipeline

  alloy/static/*.als - the formal model      Stage 0
  rules + security properties + scenarios 

  | run <scenario>
  v

  java -jar alloy6.jar exec           Stage 1
  alloy/instances/<Scenario>.xml

  |
  v scripts/parse_alloy_instance.py

  Python dict {atoms, fields, skolems} Stage 2


  |
  v scripts/instance_to_fixture.py

  alloy/fixtures/<Scenario>.json       Stage 3
  "create these rows, expect these flags"
  
  |
  v  scripts/alloy_to_fixture.py (codegen)

  server/test/.../AlloyCipherFixtureTests.cs   Stage 4
  12 generated xUnit tests

  |
  v  dotnet test

  pass / fail against SQL Server, SQLite or MySQL   Stage 5


On side stage: 
scripts/check_assertions.py
"holds"/"VIOLATED"

 scripts/mutation_test.py   wraps all of the above: plant one bug, re-run the side
                            stage and stages 1-5, record who noticed, revert.


Stages 1–4 run with one command, `python scripts/alloy_to_fixture.py --repo-root .`.
Stage 5 is an ordinary `dotnet test`.




## 5. Repository layout

HOW_IT_WORKS.md - this document
RESULTS.md - plain-language summary of the findings

alloy/
  bitwarden.als - entry point for the Alloy GUI; only `open`s the four modules below
  static/
    enums.als - OrgUserStatus, OrgUserRole
    signatures.als - one `sig` per modeled database table (+ Bool, OrgKey)
    facts.als - structural invariants (constraints every database state obeys)
    predicates.als - the access rules, the 8 security assertions, the 12 scenarios
                            - also the file the Alloy command-line tool is pointed at
  instances/*.xml - solver output, one per scenario
  fixtures/*.json - test fixtures, one per scenario
  docs/
    mutation-testing-full-sqlserver.json     raw output of the full harness run
    mutation-testing-full-linq-sqlite.json   and its LINQ-mutation pass on SQLite

scripts/
  alloy_to_fixture.py - Stages 1-4 orchestrator + C# code generator
  parse_alloy_instance.py - Stage 2
  instance_to_fixture.py - Stage 3
  alloy_checks.py - shared runner for the model's `check` commands
  check_assertions.py - CLI: run all assertions, exit 1 on any violation
  mutation_test.py - the mutation-testing harness
  pipeline_config.yaml - tool paths + enum-integer map
  alloy_test_expectations.yaml   which scenarios become tests, and how to pick the test subject
  requirements.txt - Python deps (only pyyaml)
  lib/alloy6.jar - the Alloy solver (present in this checkout, not committed to git)
tmp/ - empty check_* folders left over from an early assertion run
.mutation_test_trx/ - TRX test reports written by the harness, one per mutation
server-files/ - committed copies of the three Alloy C# test files, laid out at their
                            paths inside server/

server/ - Bitwarden server checkout - untracked by this repository's git

The C# files the pipeline reads and writes live in `server/`:
`server/test/Infrastructure.IntegrationTest/Vault/Repositories/`.

 File - Origin
`AlloyCipherFixtureTests.cs` - **Generated** by Stage 4. Never edit by hand.
`AlloyCipherFixtureHelpers.cs` - Loads a fixture and inserts its rows into the database.
`AlloyCipherAccessTests.cs` - An independent suite of 10 tests covering similar scenarios, used as the comparison baseline.

`server/` is not tracked, so copies of these three files are committed under
`server-files/`, at the same relative paths. They are what makes a fresh clone of this
repository runnable.

### 5.1 Setting up `server/` from a fresh clone

`server/` is a clone of the public Bitwarden server repository
(`https://github.com/bitwarden/server`)

```bash
# 1. Bitwarden itself, at the exact commit the model was written against
git clone https://github.com/bitwarden/server.git server
git -C server checkout c968d2546

# 2. The three Alloy test files
cp -r server-files/. server/

# 3. The Alloy solver: Alloy 6.2.0 (org.alloytools.alloy.dist, build 202501090817),
#    from https://github.com/AlloyTools/org.alloytools.alloy/releases
mkdir -p scripts/lib
cp ~/Downloads/org.alloytools.alloy.dist.jar scripts/lib/alloy6.jar
```

Why the pins matter:

- **The Bitwarden commit.** The model encodes the SQL function, the LINQ port and the
  repository code *as they are at `c968d2546`*, and the mutation catalog anchors to
  exact line numbers in those files. A newer Bitwarden may change any of them;
  then the model and the tests no longer describe the same code, and
  `mutation_test.py --dry-run` will report anchors that no longer match.
- **The JAR version.** A different solver build may pick different (equally valid)
  example databases, so the instances, fixtures and some test details would change

`AlloyCipherFixtureTests.cs` in `server-files/` is the generated file as of the last
regeneration. It can always be rebuilt from the committed instances with
`python3 scripts/alloy_to_fixture.py --repo-root . --skip-alloy`.





## 6. Stage 0 The formal model (Alloy)

### 6.1 What Alloy is, in three sentences

Alloy is a language for describing structures and the rules they must obey. Given a
model, its solver can do two things:

- **`run`**: find a concrete example that satisfies some constraint (an **instance**).
- **`check`**: search for a counterexample to a claimed property (an **assertion**).

The search is exhaustive within a **scope**, e.g. "at most 4 atoms of each type". So
"no counterexample found" means none exists in any database state up to that
size.

### 6.2 Signatures: the database tables

`alloy/static/signatures.als` declares one `sig` per table. It models only the columns that
matter for access control. The listing below is condensed.

```alloy
sig Organization { enabled: one Bool, allowAdminAccess: one Bool }
sig Cipher       { owner: one (User + Organization) }   -- user XOR org, see facts
sig Collection   { org: one Organization, ciphers: set Cipher }  -- `ciphers` = CollectionCipher table
sig OrganizationUser {
    memberOrg: one Organization, memberUser: lone User,  -- invited members have no user yet
    status: one OrgUserStatus,   role: one OrgUserRole,  key: lone OrgKey }
sig Group { groupOrg: one Organization, members: set OrganizationUser }  -- `members` = GroupUser
sig CollectionUser { cuCollection: one Collection, cuOrgUser: one OrganizationUser,
                      readOnly: one Bool, hidePasswords: one Bool, manage: one Bool }
sig CollectionGroup { cgCollection: one Collection, cgGroup: one Group,
                      readOnly: one Bool, hidePasswords: one Bool, manage: one Bool }
sig User { canSeeRel, canEditRel, canViewPasswordRel, canManageRel: set Cipher }
```

Junction tables that carry no data (`CollectionCipher`, `GroupUser`) become plain
relations (`ciphers`, `members`). This keeps the search space small. Junction tables
with permission flags (`CollectionUser`, `CollectionGroup`) stay as their own sigs.

`alloy/static/enums.als` defines `OrgUserStatus` (`Invited`, `Accepted`, `Confirmed`,
`Revoked`) and `OrgUserRole` (`Owner`, `Admin`, `Member`, `Custom`). `Member` is the
C# role `User`, renamed so it does not clash with `sig User`.

### 6.3 Facts: what every database state obeys

`alloy/static/facts.als` holds 11 structural constraints. Each one mirrors a schema
constraint or an application-level convention.

Fact -  Meaning
`CipherOwnerIsExclusive` - A cipher is owned by a user **or** an org, never both.
`CipherInCollectionSameOrg` - A collection only holds ciphers of its own org.
`PersonalCiphersNotInCollections` - Personal ciphers are never in collections.
`OrgUserInvitedHasNoUser` - A membership has no user attached **if and only if** it is still `Invited`.
`OrgUserConfirmedHasKey` - A membership has an org key **if and only if** it is `Confirmed`.
`GroupMembersSameOrg`, `CollectionUserSameOrg`, `CollectionGroupSameOrg` - No cross-organization wiring.
`CollectionUserUniquePair`, `CollectionGroupUniquePair` - At most one grant per (member, collection) and (group, collection), matching the composite primary keys.
`OrgKeyUnique` - Keys are not shared.

One constraint is deliberately **absent**: nothing says a user has at most one
membership per organization. The real schema does not enforce that either.


### 6.4 Predicates: the access rules

`alloy/static/predicates.als` encodes the rules as predicates. Many of the
comments above the predicates point to the SQL or C# they mirror; this copy's comments
are shorter than the earlier version's, and the table below names the source for each
layer. There are three paths to access.

1. **Personal:** `c.owner = u`.
2. **Admin bypass:** a confirmed `Owner`/`Admin` in an enabled org with `allowAdminAccess = True`.
3. **Collection grants:** a confirmed member of an enabled org holds a direct or group
   grant on a collection containing `c`.

The building blocks for path 3 (parameter types omitted for brevity):

```alloy
pred isConfirmedMember[ou, o] { ou.memberOrg = o and ou.status = Confirmed } -- CTE: Status = 2
pred directGrant[ou, col]  { some cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col }
pred groupGrant[ou, col] {  -- the null-guard
    (no cu: CollectionUser | cu.cuOrgUser = ou and cu.cuCollection = col)   -- no direct grant...
    and (some g: Group, cg: CollectionGroup |    -- ...and a real group path
         ou in g.members and cg.cgGroup = g and cg.cgCollection = col)
}
```

The parentheses in `groupGrant` matter. In Alloy a quantifier swallows everything to
its right, so without them `and (some g ...)` would be absorbed into the `no cu | ...`
body and the predicate would change meaning. Mutation `A1`  reproduces exactly
that bug.

`canSee` needs only the existence of a grant. `canEdit`, `canViewPassword` and
`canManage` must reproduce the **winning-row** selection from 3.2, which the model
does in layers.

Predicate - Job - Mirrors

`resolvedEdit` / `resolvedViewPassword` / `resolvedManage`
- The flag for one (membership, collection) pair, direct before group
- `COALESCE(CU.x, CG.x, 0)`

`collectionBeats`, `winningCollection`
- The best collection for one membership
- `OrderByDescending(Manage).ThenBy...(Edit).ThenBy...(ViewPassword)`

`isCandidateRow`, `rowBeats`, `winningRow`
- The single best row across **all** of the user's memberships and collections
- `GroupBy(Cipher.Id)...First()`, which ignores where a row came from

`isCandidateGroupGrant`, `cgBeats`, `winningGroupGrant`
- If several groups grant the same collection, pick one group row rather than mixing flags from different rows
- same ordering

`finalEdit` / `finalViewPassword` / `finalManage`
- Read the flag off that single winning row

So `canEdit[u, c]` reads: "u owns c, **or** u has the admin bypass, **or** the
winning row for (u, c) has `finalEdit`." Booleans have no order in Alloy, so
"strictly beats" is spelled out key by key:

```alloy
pred collectionBeats[ou, colA, colB] {
    (resolvedManage[ou, colA] and not resolvedManage[ou, colB])
    or ((resolvedManage[ou, colA] iff resolvedManage[ou, colB])
        and resolvedEdit[ou, colA] and not resolvedEdit[ou, colB])
    or ((resolvedManage[ou, colA] iff resolvedManage[ou, colB])
        and (resolvedEdit[ou, colA] iff resolvedEdit[ou, colB])
        and resolvedViewPassword[ou, colA] and not resolvedViewPassword[ou, colB])
}
```

### 6.5 Assertions: the security properties

There are eight `assert` blocks. Each is a claim that must hold in every database state.

Assertion - Claim
`RevokedCannotSee` - revoked member cannot see any org cipher.
`DisabledOrgBlocksAccess` - Nobody sees any cipher of a disabled org.
`UncollectedCipherInvisible` - An org cipher in no collection is invisible to everyone except bypass admins.
`PersonalCipherIsPrivate` - Nobody but its owner sees a personal cipher.
`ReadOnlyPreventsEdit` - If every grant a (non-bypass) user holds on a cipher is ReadOnly, they cannot edit it.
`HidePasswordsPreventsViewPassword` - Same for HidePasswords, cannot view password.
`NoManageGrantPreventsManage` - If no grant has Manage, the user cannot manage.
`NoAccessWithoutGrant` - A confirmed, non-bypass member with **zero** grants on any collection containing a collected cipher cannot see it.

Some assertions are written from the raw relations
instead of reusing `groupGrant` and friends. That way a bug in the predicates cannot
also silently corrupt the property that is supposed to catch it.

### 6.6 Run commands: the test scenarios

There are twelve run commands. Each describes a scenario precisely enough that
any solution the solver finds exercises one specific branch of the real code. Each
one becomes one generated test. The example followed through the rest of this
document is the most important one.

```alloy
run WinningRowDivergenceExists {
    some u: User, c: Cipher, ou: OrganizationUser, colA, colB: Collection, cuA, cuB: CollectionUser |
        c.owner in Organization
        and (c.owner & Organization).enabled = True
        and (c.owner & Organization).allowAdminAccess = False          -- rule out the bypass path
        and ou.memberUser = u and isConfirmedMember[ou, c.owner & Organization]
        and c in colA.ciphers and c in colB.ciphers and colA != colB    -- same cipher, two collections
        and cuA.cuOrgUser = ou and cuA.cuCollection = colA
        and cuA.manage = False and cuA.readOnly = False and cuA.hidePasswords = True   -- Edit only
        and cuB.cuOrgUser = ou and cuB.cuCollection = colB
        and cuB.manage = False and cuB.readOnly = True  and cuB.hidePasswords = False  -- ViewPassword only
        and canEdit[u, c] and not canViewPassword[u, c]                 -- the winning-row outcome
} for 5 but 1 Cipher, 2 Collection, 1 OrganizationUser
```

The scope `for 5 but 1 Cipher, 2 Collection, 1 OrganizationUser` means at most 5
atoms of each type, but at most 1 cipher, 2 collections and 1 membership. Alloy
scopes are upper bounds; the scenario's own constraints then force exactly that many
here. The tight bounds are deliberate. They remove room for the solver to satisfy the scenario some
other way, e.g. with a second membership whose group grant has Manage = true and
outranks everything.

The run commands also force each scenario down a single access path. Five of the
twelve (`canSeeExists`, `ManagePathExists`, `GroupGrantOnlyExists`,
`NoAccessWithoutGrantScenario`, `WinningRowDivergenceExists`) state
`allowAdminAccess = False` outright, so the solver cannot cheat through the admin
bypass, which the SQL does not implement. The others pin specific grant flags, a
revoked status, or a disabled org instead.

The twelve scenarios, with the answers the solver computed for each:

Scenario - Real-code branch exercised  - | see | edit | view pw | manage |

`canSeeExists` - direct grant  - | 1 | 0 | 1 | 0 |
`ReadOnlyPathExists` - `ReadOnly = 1 -> Edit = 0`  - | 1 | 0 | 1 | 0 |
`HidePasswordsPathExists` - `HidePasswords = 1 -> ViewPassword = 0` -  | 1 | 0 | 0 | 0 |
`ManagePathExists` - `Manage = 1`  - | 1 | 1 | 1 | 1 |
`GroupGrantOnlyExists` - group path (no direct grant)  - | 1 | 1 | 1 | 0 |
`DirectGrantPrecedesGroupGrant` - direct ReadOnly grant beats a writable group grant  - | 1 | 0 | 1 | 1 |
`WinningRowDivergenceExists` - two rows, tie-break on Edit -  | 1 | 1 | 0 | 0 |
`RevokedMemberScenario` - status gate  - | 0 | | | |
`DisabledOrgScenario` - `Enabled = 1` join  - | 0 | | | |
`UncollectedCipherScenario` - `WHERE` needs a grant; cipher in no collection - | 0 | | | |
`NoAccessWithoutGrantScenario` - `WHERE` needs a grant; cipher collected, but member has none - | 0 | | | |
`PersonalPrivacyScenario` - personal branch filters by owner | 0 | | | |

One quirk specific to this copy: in `ReadOnlyPathExists` the line
`and cu.cuOrgUser = ou and cu.cuCollection = col and cu.readOnly = True` appears twice.
The repeat is logically redundant, so the scenario means exactly the same thing, but
it changes the formula handed to the SAT solver. The solver therefore picks a
different (equally valid) witness: three ciphers instead of four, with the test
subject `Cipher$2`. The expected flags are unchanged.


### 6.7 Materialized flags: the solver writes the expected answer

The file ends with one more fact:

```alloy
fact MaterializedFlags {
    all u: User, c: Cipher | c in u.canSeeRel          iff canSee[u, c]
    all u: User, c: Cipher | c in u.canEditRel         iff canEdit[u, c]
    all u: User, c: Cipher | c in u.canViewPasswordRel iff canViewPassword[u, c]
    all u: User, c: Cipher | c in u.canManageRel       iff canManage[u, c]
}
```

The four `...Rel` fields on `User` have no database column. Their only job is to make
the solver record the model's own answer for every (user, cipher) pair *inside the
instance it outputs*. The fields are otherwise unconstrained, so this never changes
which scenarios are satisfiable. As a result, **no human ever types an expected test
outcome**: every assertion in every generated test is computed by the model.

**What Stage 0 accomplishes:** checkabl statement of
Bitwarden's cipher access rules, eight security claims about them, and twelve
scenario descriptions that are ready to become tests.



## 7. Stage 1 - Solving a scenario: `.als` to instance XML

**Code:** `scripts/alloy_to_fixture.py`, function `_run_alloy()`.

For each scenario named in `scripts/alloy_test_expectations.yaml`, the orchestrator
runs Alloy's headless CLI:

```bash
java -jar scripts/lib/alloy6.jar exec -c WinningRowDivergenceExists -t xml -q -f -o <tmpdir> alloy/static/predicates.als
```

#### How it works, step by step

1. **Read the scenario list.** `main()` loads `scripts/pipeline_config.yaml` (JAR path,
   model path, output folders) and the `runs:` map from
   `scripts/alloy_test_expectations.yaml`. Only scenarios listed in that YAML are
   processed. A `run` command that exists in the model but not in the YAML is silently
   ignored.
2. **Call the solver once per scenario.** `_run_alloy()` checks that the JAR exists,
   creates a fresh temporary directory, and runs the command above with Python's
   `subprocess.run`. The flags:
   - `exec`: the JAR's headless mode, no GUI.
   - `-c <name>`: which command to execute.
   - `-t xml`: write solutions as XML.
   - `-q`: quiet.
   - `-f`: allow writing into the output directory. This wipes the directory first,
     which is why each scenario gets its own temp directory instead of writing straight
     into `alloy/instances/`.
   - `-o <dir>`: where to write.
3. **Inside the solver.** Alloy translates the model, the facts, the scenario's
   constraint and the scope into one large Boolean formula and
   hands it to a SAT solver. Any satisfying assignment of that formula is a database
   state: which atoms exist, and which tuples each field contains. The solver writes the
   first one it finds as `<name>-solution-0.xml`.
4. **Interpret the result.**
   - A non-zero exit code means something broke before solving (bad path, Java
     error). `_run_alloy()` raises an error.
   - Exit code 0 and a solution file: the scenario is satisfiable. The file is moved to
     `alloy/instances/<Scenario>.xml`, replacing the previous version.
   - Exit code 0 but **no** solution file: the scenario is **UNSAT**. No database state
     within scope fits it. The exit code doesn't distinguish this case, so the missing
     file is the only signal. The orchestrator raises an error rather than silently
     reusing the stale XML from the last run. For mutation testing this is a meaningful
     result: "the planted bug made this scenario impossible".

It points at `alloy/static/predicates.als` rather than `alloy/bitwarden.als` because
the CLI only finds commands in the root module it is given, not in modules that
module `open`s. The four modules are declared with a folder prefix (`module
static/predicates`, `open static/signatures`, ...), matching how `bitwarden.als` opens
them from one level up; Alloy resolves these names without trouble when
`predicates.als` itself is the root.

#### How the XML is laid out

The instance XML has four kinds of elements inside `<instance>`. Stage 2 relies on
this layout.

Element - Meaning - Example

`<sig label="..." ID="n">` with `<atom>` children
- A type, and which atoms of it exist in this world. Labels carry a module prefix.
- `<sig label="signatures/Organization" ID="14">` holding `Organization$0`, `Organization$1` |

`<field label="..." parentID="n">` with `<tuple>` children
- A relation. Each `<tuple>` lists one (source atom, target atom) pair. `parentID` is the ID of the sig that declares the field. A `<types>` child records the column types.
- `enabled`: (`Organization$0`, `False$0`)

`<skolem label="$Run_var">`
- Which atom the solver picked for each `some` variable in the run command.
- `$WinningRowDivergenceExists_u` -> `User$0`

Built-in sigs (`univ`, `Int`, `seq/Int`, `String`)
- Alloy's own universe; not part of the model.

Some details matter for the conversion:
- **Enum values are atoms too.** A `one sig Confirmed extends OrgUserStatus` becomes a
  sig `enums/Confirmed` with the single atom `enums/Confirmed$0`. The abstract parent
  `enums/OrgUserStatus` is listed with no atoms. `Bool` works the same way (`True$0`,
  `False$0`).
- **An empty relation is still listed**, with a `<types>` child but no `<tuple>`. That
  is how "this user can *not* view the password" shows up (`canViewPasswordRel`
  below).
- **One field label can appear twice.** `readOnly` is declared on both
  `CollectionUser` and `CollectionGroup`, so the file holds two `<field
  label="readOnly">` elements with different `parentID`s.

**Example output** — `alloy/instances/WinningRowDivergenceExists.xml` (287 lines).
This is the file the regeneration on 2026-10-05 produced.
Excerpts, condensed: most `<types>` lines and
the skolems' `ID` attributes are left out, and each skolem is put on one line.

```xml
<instance ... command="Run WinningRowDivergenceExists for 5 but 1 Cipher, 2 Collection, 1 OrganizationUser">

<sig label="signatures/Organization" ID="14" parentID="2">
   <atom label="signatures/Organization$0"/>
   <atom label="signatures/Organization$1"/>
</sig>
<field label="enabled" ID="15" parentID="14">
   <tuple> <atom label="signatures/Organization$0"/> <atom label="signatures/False$0"/> </tuple>
   <tuple> <atom label="signatures/Organization$1"/> <atom label="signatures/True$0"/> </tuple>
</field>

<field label="readOnly" ID="35" parentID="32">          <!-- on CollectionUser -->
   <tuple> <atom label="signatures/CollectionUser$0"/> <atom label="signatures/True$0"/> </tuple>
   <tuple> <atom label="signatures/CollectionUser$1"/> <atom label="signatures/False$0"/> </tuple>
</field>

<!-- The model's own verdict, thanks to MaterializedFlags: -->
<field label="canSeeRel" ID="9" parentID="8">
   <tuple> <atom label="signatures/User$0"/> <atom label="signatures/Cipher$0"/> </tuple>
</field>
<field label="canEditRel" ID="11" parentID="8">
   <tuple> <atom label="signatures/User$0"/> <atom label="signatures/Cipher$0"/> </tuple>
</field>
<field label="canViewPasswordRel" ID="12" parentID="8">   <!-- empty: cannot view password -->
   <types> <type ID="8"/> <type ID="10"/> </types>
</field>

<!-- Skolems: which atom the solver bound to each `some` variable -->
<skolem label="$WinningRowDivergenceExists_u"> <tuple> <atom label="signatures/User$0"/> </tuple> </skolem>
<skolem label="$WinningRowDivergenceExists_c"> <tuple> <atom label="signatures/Cipher$0"/> </tuple> </skolem>
<skolem label="$WinningRowDivergenceExists_colA"> <tuple> <atom label="signatures/Collection$1"/> </tuple> </skolem>
<skolem label="$WinningRowDivergenceExists_cuA"> <tuple> <atom label="signatures/CollectionUser$1"/> </tuple> </skolem>
```

The solver is free to add "decoy" atoms that the scenario does not mention. Here it
added a disabled `Organization$0` and a `Group$1` whose group grants have no members.
These decoys matter: they become real database rows, so the test also checks that
irrelevant data does not leak into the answer.

**What Stage 1 accomplishes:** a concrete, machine-found database state that provably
satisfies the scenario, plus the model's verdict on it.





## 8. Stage 2 - Parsing the instance: XML to Python dict

**Code:** `scripts/parse_alloy_instance.py`, `parse_instance(xml_path)`.

It turns the XML into a plain Python dictionary with four keys:
`{command, atoms, fields, skolems}`. It uses only the standard library's
`xml.etree.ElementTree`.

#### How it works, step by step

1. **Find the instance.** The root element may be `<alloy>` or `<instance>`. The parser
   locates the `<instance>` element either way, and stores its `command` attribute (the
   full `Run ... for ...` text) as `command`.

2. **Build `atoms`: atom -> type.** For every `<sig>`, it strips the module prefix from
   the label (`_strip_module_prefix` keeps only what follows the last `/`, so
   `signatures/User` becomes `User`). It skips Alloy's built-in sigs and records every
   child `<atom>` under that type, also without prefix: `atoms["User$0"] = "User"`.
   - If an atom were listed under two sigs, the first one would win.
   - In practice enum atoms appear only under their concrete sig, so `Confirmed$0` maps
     to `Confirmed` and `True$0` to `True`. That bare name is what Stage 3 later looks
     up to get the database integer.

3. **Build `skolems`: variable -> atom.** For every `<skolem>`, it drops the leading
   `$` from the label and records the first atom of its first tuple:
   `skolems["WinningRowDivergenceExists_u"] = "User$0"`.

4. **Build `fields`: relation -> list of pairs.** For every `<field>`, it reads each
   `<tuple>` that has exactly two atoms, strips both prefixes, and appends
   `(source, target)` to `fields[label]`. Relations with no tuples get no entry at all,
   so an empty relation simply reads as "no targets".
   - If the label already exists (the second `readOnly`), the new tuples are
     **appended**, not overwritten. Both `CollectionUser` and `CollectionGroup` tuples
     survive in one list.
   - `parentID` is deliberately ignored. The two kinds are told apart later by their
     *source* atom: a lookup for `CollectionUser$0` only ever matches tuples whose
     source is `CollectionUser$0`.

The four helpers that Stage 3 uses to query the result are all simple list scans:

Helper - Returns - Example:

`atom_type(parsed, a)` 
-the type of atom `a`
-`atom_type(..., "Confirmed$0")` -> `"Confirmed"`

`atoms_of_type(parsed, t)`
- all atoms of type `t`
- `atoms_of_type(..., "Collection")` -> `["Collection$0", "Collection$1"]`

`field_targets(parsed, f, src)`
- every target of `src` in relation `f`
- `field_targets(..., "readOnly", "CollectionUser$0")` -> `["True$0"]`

`field_source(parsed, f, tgt)`
- every source pointing at `tgt` in `f`
- `field_source(..., "ciphers", "Cipher$0")` -> both collections

**One concrete conversion.** This XML fragment:

```xml
<field label="status" ID="24" parentID="21">
   <tuple> <atom label="signatures/OrganizationUser$0"/> <atom label="enums/Confirmed$0"/> </tuple>
   <types> <type ID="21"/> <type ID="25"/> </types>
</field>
```

becomes the dictionary entry `fields["status"] = [("OrganizationUser$0",
"Confirmed$0")]`, alongside `atoms["Confirmed$0"] = "Confirmed"` from the
`enums/Confirmed` sig.

**Example output** - running the module directly prints a summary (real output; `...`
marks omitted lines). The four `readOnly` lines show the accumulation: two
`CollectionUser` tuples and two `CollectionGroup` tuples share one field label.

```
$ python3 scripts/parse_alloy_instance.py alloy/instances/WinningRowDivergenceExists.xml
Command: Run WinningRowDivergenceExists for 5 but 1 Cipher, 2 Collection, 1 OrganizationUser
Atoms (24):
  'Accepted$0'                   → Accepted
  'Admin$0'                      → Admin
  'Cipher$0'                     → Cipher
  'Collection$0'                 → Collection
  'Collection$1'                 → Collection
  ...
Fields (20):
  'allowAdminAccess'       : Organization$0 → True$0
  'allowAdminAccess'       : Organization$1 → False$0
  'canEditRel'             : User$0 → Cipher$0
  'canSeeRel'              : User$0 → Cipher$0
  ...
  'readOnly'               : CollectionUser$0 → True$0
  'readOnly'               : CollectionUser$1 → False$0
  'readOnly'               : CollectionGroup$0 → True$0
  'readOnly'               : CollectionGroup$1 → False$0
  'role'                   : OrganizationUser$0 → Custom$0
  'status'                 : OrganizationUser$0 → Confirmed$0
```

The summary doesn't print the skolems, but the returned dict holds them (real value):
`{'WinningRowDivergenceExists_u': 'User$0', 'WinningRowDivergenceExists_c': 'Cipher$0',
'WinningRowDivergenceExists_ou': 'OrganizationUser$0', 'WinningRowDivergenceExists_colA':
'Collection$1', 'WinningRowDivergenceExists_colB': 'Collection$0',
'WinningRowDivergenceExists_cuA': 'CollectionUser$1', 'WinningRowDivergenceExists_cuB':
'CollectionUser$0'}`.

**What Stage 2 accomplishes:** a clean, queryable, prefix-free view of the instance.



## 9. Stage 3 - Building a fixture: dict -> JSON

**Code:** `scripts/instance_to_fixture.py`, `build_fixture()`. Config comes from
`scripts/alloy_test_expectations.yaml` and `scripts/pipeline_config.yaml`.

It does three things.

**1. Pick the test subject** - which user queries the database, and which cipher to
look for.

- **First choice: skolems.** If the run command names its variables `u` and `c`, the
  XML records exactly which atoms satisfy the scenario (`$<Scenario>_u`,
  `$<Scenario>_c`). These are authoritative.

- **Fallback: a named derivation rule** from `alloy_test_expectations.yaml`, such as
  `find_user_with_org_access` or `find_user_not_cipher_owner`. These rules scan the
  instance heuristically. Only `PersonalPrivacyScenario` needs one, and only for its
  user: its variables are `u1`, `u2` and `c`. The cipher comes from the `c` skolem,
  but the subject user has to be `u2`, the one who must *not* see the item, so
  `find_user_not_cipher_owner` picks it.

The YAML entry for our example (skolems win, so the rules listed are not used):

```yaml
  WinningRowDivergenceExists:
    test_user:   find_user_with_org_access
    test_cipher: find_cipher_in_collection
```

**2. Read the expected outcome from the instance.** It reads the answer the solver
wrote via `MaterializedFlags`:

```python
can_see = test_cipher in pai.field_targets(parsed, "canSeeRel", test_user)
# if visible, likewise read canEditRel / canViewPasswordRel / canManageRel;
# if not visible, expected = {"can_see": False} only
```

If the cipher is not visible, `expected` is just `{"can_see": false}`. The other three
flags would be meaningless, since the real database returns no row to read them from.

**3. Translate every atom into a table row.** There is one `_build_*` function per
table. Each loops over the atoms of one type (`atoms_of_type`) and reads that atom's
fields with `field_targets`. Every per-atom field it reads is declared `one` or `lone`
in the model, so it takes the first (only) target. The two `set` relations
(`ciphers`, `members`) are instead turned into one row per tuple.

Fixture list - Built from, Fields read -> JSON keys, Conversion

`users`
- `User` atoms
- only `alloy_id`; the `...Rel` fields are not exported 

`organizations`
- `Organization` atoms
- `enabled`, `allowAdminAccess` -> `enabled`, `allow_admin_access`
- Bool atom -> `true`/`false`

`ciphers`
- `Cipher` atoms
- `owner` -> `owner_org` **or** `owner_user`
- looks at the *type* of the owner atom to decide which key to fill; the other is `null`

`collections`
- `Collection` atoms
- `org` -> `org_id`

`collection_ciphers`
- every tuple of the `ciphers` relation
- (collection, cipher) -> `collection_id`, `cipher_id`
- one row per tuple: the relation *is* the junction table

`organization_users`
- `OrganizationUser` atoms
- `memberOrg`, `memberUser`, `status`, `role`, `key` -> `org_id`, `user_id`, `status`, `type`, `has_key`
- status and role -> integers; `user_id` is `null` for an invited member; `has_key` is `true` if any key atom is linked

`groups`
- `Group` atoms
- `groupOrg` -> `org_id`

`group_users`
- every tuple of the `members` relation
- (group, member) -> `group_id`, `org_user_id`
- one row per tuple

`collection_users`
- `CollectionUser` atoms
- `cuCollection`, `cuOrgUser`, `readOnly`, `hidePasswords`, `manage`
- Bool atoms -> `true`/`false`

`collection_groups`
- `CollectionGroup` atoms
- `cgCollection`, `cgGroup`, and the same three flags

The enum conversion is two steps.
1. `_bare_enum_name` cuts the `$N` suffix: `Confirmed$0` becomes `Confirmed`.
2. That name is looked up in `pipeline_config.yaml`'s `enum_values`:
   - status: `Invited 0`, `Accepted 1`, `Confirmed 2`, `Revoked -1`
   - role: `Owner 0`, `Admin 1`, `Member 2`, `Custom 4`
   - Bool: `"True" 1`, `"False" 0`

An unknown name raises an error rather than guessing. These are the integers
Bitwarden's C# enums use, so the test helper can cast them directly. Continuing the
Stage 2 example: `fields["status"] = [("OrganizationUser$0", "Confirmed$0")]` ->
`Confirmed` -> `2` -> `"status": 2`.

The CollectionUser/CollectionGroup split from Stage 2 resolves itself here. The
`collection_users` builder only ever asks for the `readOnly` targets of
`CollectionUser$...` atoms, and `collection_groups` only for `CollectionGroup$...` atoms.

`alloy_id` (e.g. `"User$0"`) is a symbolic name. Rows refer to each other by it
(`"org_id": "Organization$1"`), and Stage 5 swaps every one for a real database ID.

**How the fallback rules work.** Each rule is a short scan over the parsed instance:

- `find_user_with_org_access`: builds lookup tables (membership -> user, direct grant ->
  membership, group -> its group grants). It returns the user of the first confirmed
  membership, in sorted order, that has a direct grant or belongs to a group with a
  group grant.
- `find_user_not_cipher_owner`: returns the first user that is not the `owner` of any
  cipher.
- `find_user_with_group_grant_only`: returns the user of a confirmed membership with a
  group grant on some collection where it has no direct grant.
- `find_cipher_in_collection` / `find_cipher_not_in_collection` /
  `find_personal_cipher`: return the first cipher that appears / does not appear in the
  `ciphers` relation / is owned by a user.

A rule is consulted only when the matching skolem is missing. It picks a plausible atom,
not a proven one, which is why skolems come first.

Finally, `alloy_to_fixture.py` writes the dictionary to
`alloy/fixtures/<Scenario>.json` with `json.dump(..., indent=2)`.

**Example output** — `alloy/fixtures/WinningRowDivergenceExists.json` (complete; only
the whitespace is compacted). Re-running Stage 3 on the committed XML reproduces all
12 committed fixtures exactly.

```json
{
  "name": "WinningRowDivergenceExists",
  "alloy_command": "Run WinningRowDivergenceExists for 5 but 1 Cipher, 2 Collection, 1 OrganizationUser",
  "expected":     { "can_see": true, "can_edit": true, "can_view_password": false, "can_manage": false },
  "test_subject": { "user": "User$0", "cipher": "Cipher$0" },
  "entities": {
    "users":         [ { "alloy_id": "User$0" } ],
    "organizations": [ { "alloy_id": "Organization$0", "enabled": false, "allow_admin_access": true },
                       { "alloy_id": "Organization$1", "enabled": true,  "allow_admin_access": false } ],
    "ciphers":       [ { "alloy_id": "Cipher$0", "owner_org": "Organization$1", "owner_user": null } ],
    "collections":   [ { "alloy_id": "Collection$0", "org_id": "Organization$1" },
                       { "alloy_id": "Collection$1", "org_id": "Organization$1" } ],
    "collection_ciphers": [ { "collection_id": "Collection$0", "cipher_id": "Cipher$0" },
                            { "collection_id": "Collection$1", "cipher_id": "Cipher$0" } ],
    "organization_users": [ { "alloy_id": "OrganizationUser$0", "org_id": "Organization$1",
                              "user_id": "User$0", "status": 2, "type": 4, "has_key": true } ],
    "groups":        [ { "alloy_id": "Group$0", "org_id": "Organization$0" },
                       { "alloy_id": "Group$1", "org_id": "Organization$1" } ],
    "group_users":   [],
    "collection_users": [
      { "collection_id": "Collection$0", "org_user_id": "OrganizationUser$0",
        "read_only": true,  "hide_passwords": false, "manage": false },
      { "collection_id": "Collection$1", "org_user_id": "OrganizationUser$0",
        "read_only": false, "hide_passwords": true,  "manage": false } ],
    "collection_groups": [
      { "collection_id": "Collection$1", "group_id": "Group$1", "read_only": true,  "hide_passwords": false, "manage": false },
      { "collection_id": "Collection$0", "group_id": "Group$1", "read_only": false, "hide_passwords": true,  "manage": true } ]
  }
}
```

Reading this fixture as a story:

- `User$0` is a confirmed Custom-role member of `Organization$1`, which is enabled and
  has no admin bypass.
- `Cipher$0` is in two collections.
- The user has a direct grant on each. `Collection$1` gives Edit only, `Collection$0`
  gives ViewPassword only.
- The group grants belong to `Group$1`, which has no members, so they are noise. They
  would be ignored anyway, because a direct grant exists for both collections.
- The model says: can see, can edit, **cannot** view the password, cannot manage.

**What Stage 3 accomplishes:** a self-contained recipe
It is committed to git, so any
change to the scenarios shows up as a reviewable diff.

---

## 10. Stage 4 — Generating C# tests: JSON -> `.cs`

**Code:** `scripts/alloy_to_fixture.py`: `generate_cs_file()`, `_generate_test_method()`,
`_generate_assertions()`.

After all fixtures are built, the orchestrator writes one C# file,
`server/test/Infrastructure.IntegrationTest/Vault/Repositories/AlloyCipherFixtureTests.cs`,
containing two types.

- **`AlloyCipherFixtureData`**: a dictionary with every fixture's JSON embedded as a
  C# raw string literal. The test binary therefore needs no file paths at runtime.
- **`AlloyCipherFixtureTests`**: one test method per fixture, named
  `<Scenario>_MatchesTvf`.

#### How it works, step by step

The generator is plain string assembly. There is no C# tooling or template engine; the
fixed parts of the file are Python string constants (`_CS_HEADER`,
`_CS_FIXTURE_DATA_OPEN`, `_CS_CLASS_OPEN`, `_COMMON_PARAMS`,
`_COMMON_FIXTURE_SETUP`, ...) and `generate_cs_file()` concatenates them in order:

1. **Header.** An "AUTO-GENERATED ... do not edit" comment, the `using` lines, and the
   namespace `Bit.Infrastructure.IntegrationTest.Vault.Repositories`.

2. **The data class.** For each fixture, `json.dumps(fixture, separators=(",", ":"))`
   produces the JSON on one compact line. It is wrapped in a C# raw string literal
   (`"""..."""`), so the JSON's own double quotes need no escaping, and added as a
   dictionary entry keyed by the scenario name. Any `"""` inside the JSON would be
   escaped first, though JSON from this pipeline never contains one.

3. **The test class.** For each fixture, `_generate_test_method()` emits:
   - `[DatabaseTheory, DatabaseData]` and the signature
     `public async Task <Scenario>_MatchesTvf(...)` with the seven repository
     parameters;
   - the shared setup: `LoadFixture("<Scenario>")` and `CreateEntitiesFromFixture(...)`;
   - `var results = await cipherRepository.GetManyByUserIdAsync(userId);`
   - the assertion lines from `_generate_assertions()`.
4. **Write.** The whole string replaces the generated `.cs` file.

`_generate_assertions()` emits assertions only for keys present in `expected`:

- `can_see: false` produces `Assert.DoesNotContain(results, c => c.Id == cipherId)`
  and stops there.
- `can_see: true` produces `var details = results.FirstOrDefault(c => c.Id ==
  cipherId);` and `Assert.NotNull(details);`, then one `Assert.True(...)` or
  `Assert.False(...)` per flag: `can_edit` -> `details.Edit`, `can_view_password` ->
  `details.ViewPassword`, `can_manage` -> `details.Manage`.

At test time, the `AlloyCipherFixtureHelpers.LoadFixture(name)` reads the
JSON string back out of the dictionary. It deserializes it with `System.Text.Json`,
using `JsonNamingPolicy.SnakeCaseLower`, into small C# classes (`AlloyCipherFixture`,
`FixtureUser`, `FixtureCipher`, ...). That policy is what maps the Python-side
`allow_admin_access` onto the C# property `AllowAdminAccess`.

**Example output** - the generated file, condensed to our scenario. Re-running the
generator on the committed fixtures reproduces the live file in `server/`.
In the real file the parameters are one per line and the setup lines
are indented four extra spaces.

```csharp
// AUTO-GENERATED by scripts/alloy_to_fixture.py  !do not edit!!.
// Source: alloy/static/predicates.als, scripts/alloy_test_expectations.yaml

internal static class AlloyCipherFixtureData
{
    public static readonly Dictionary<string, string> Fixtures = new()
    {
        ["WinningRowDivergenceExists"] = """
            {"name":"WinningRowDivergenceExists","alloy_command":"Run WinningRowDivergenceExists for 5 ...","expected":{...},...}
            """,
        // ... one entry per scenario
    };
}

public class AlloyCipherFixtureTests
{
    // ... 11 other test methods, one per scenario; this one is last in the file

    [DatabaseTheory, DatabaseData]
    public async Task WinningRowDivergenceExists_MatchesTvf(
        IUserRepository userRepository, /* ...5 more repositories injected... */ ICipherRepository cipherRepository)
    {
        var fixture = AlloyCipherFixtureHelpers.LoadFixture("WinningRowDivergenceExists");
        var (userId, cipherId) = await AlloyCipherFixtureHelpers.CreateEntitiesFromFixture(
            fixture, userRepository, organizationRepository, organizationUserRepository,
            collectionRepository, collectionCipherRepository, groupRepository, cipherRepository);

        var results = await cipherRepository.GetManyByUserIdAsync(userId);

        var details = results.FirstOrDefault(c => c.Id == cipherId);
        Assert.NotNull(details);
        Assert.True(details.Edit);
        Assert.False(details.ViewPassword);
        Assert.False(details.Manage);
    }
}
```

The console reports `Wrote .../AlloyCipherFixtureTests.cs (12 test methods).`

**What Stage 4 accomplishes:** twelve xUnit integration tests whose inputs and
expected outputs both come from the formal model, with nothing typed by hand.



## 11. Stage 5 - Running the tests against a real database

### 11.1 What happens inside one test

`AlloyCipherFixtureHelpers.CreateEntitiesFromFixture` is the bridge from
fixture to database. It writes nothing with raw SQL. It goes through **Bitwarden's own
repository classes**, the same ones the product uses, so the rows have exactly the
shape real Bitwarden code produces.

It keeps one dictionary, `idMap`, from symbolic id (`"User$0"`) to the real GUID the
database assigned. Bitwarden's `CreateAsync` always generates a fresh ID and
overwrites any preset one. So the helper reads the ID back after each insert rather
than choosing it up front. It also makes a random 8-character `runTag` and puts it in
names and emails, so repeated runs on the same database never collide.

Rows are inserted in foreign-key order, so everything a row refers to already exists:

Step - Fixture list -  Repository call - What it does with the fixture values

1. `users`
    - `userRepository.CreateAsync`
    - dummy name/email (with `runTag`) and API key; nothing access-relevant

2. `organizations`
    - `organizationRepository.CreateAsync`
    - sets `Enabled` and `AllowAdminAccessToAllCollectionItems` from the fixture. Everything else is fixed filler for a valid organization: an Enterprise plan with `UseGroups` and `UseCustomPermissions` on, placeholder keys and licence, an expiry date a year out

3. `ciphers`
    - `cipherRepository.CreateAsync`
    -  a Login cipher with `UserId` or `OrganizationId` set from `owner_user`/`owner_org` (via `idMap`) and empty data `"{}"`

4. `collections`
    - `collectionRepository.CreateAsync`
    - `OrganizationId` from `org_id`

5. `organization_users`
    - `organizationUserRepository.CreateAsync`
    - `Status` and `Type` cast straight from the fixture integers; `UserId` may be null; `Key` set to a placeholder string when `has_key` is true

6. `groups`
    - `groupRepository.CreateAsync(group, collections: [])`
    - empty group; its collection grants come in step 10

7. `group_users`
    - `groupRepository.UpdateUsersAsync`
    - grouped by group, one call per group with all its members

8. `collection_ciphers`
    - `collectionCipherRepository.UpdateCollectionsForAdminAsync`
    -  grouped by cipher, one call per cipher with all its collections

9. `collection_users`
    - `collectionRepository.UpdateUsersAsync`
    - grouped by collection, one call per collection with every member's `ReadOnly`/`HidePasswords`/`Manage`

10. `collection_groups`
    - `groupRepository.ReplaceAsync`
    -  grouped by group, one call per group with every collection's three flags

It returns `(idMap[test_subject.user], idMap[test_subject.cipher])`, the real IDs of
the test subject. The generated test then calls the real `GetManyByUserIdAsync` for
that user. That call runs the real SQL function (or its LINQ port) and the real
winning-row selection, and the test checks the answer.

For our example, on SQL Server the function returns **two** rows for `Cipher$0`. This
was confirmed by querying `dbo.UserCipherDetails` directly for the rows a test run
created. The repository chooses between them:

Row from :  | Manage | Edit | ViewPassword |
`Collection$1` (ReadOnly = 0, HidePasswords = 1) : | 0 | **1** | 0 | -- wins: ties on Manage, higher Edit
`Collection$0` (ReadOnly = 1, HidePasswords = 0) : | 0 | 0 | 1 |

Result: Edit = true, ViewPassword = false, Manage = false. That matches the model,
and the test passes.


### 11.2 Choosing the database

The test methods never pick a database themselves; Bitwarden's own test attribute
`[DatabaseData]` (`server/test/Infrastructure.IntegrationTest/DatabaseDataAttribute.cs`)
does. When xUnit asks it for test cases, it:

1. **Reads the configuration.** Sources are .NET user secrets, environment variables
   starting with `BW_TEST_`, and the command line. It expects a list of `Databases`,
   each with a `Type`, a `ConnectionString` and optional `UseEf`/`Enabled` flags. The
   double underscore in `BW_TEST_DATABASES__0__TYPE` is how .NET spells "item 0 of the
   `Databases` list" in an environment variable.

2. **Builds one dependency-injection container per configured database.** SQL Server
   without `UseEf` gets the **Dapper** repositories, which call the real T-SQL function.
   Everything else (SQLite, MySQL, Postgres, or SQL Server with `UseEf`) gets the
   **Entity Framework** repositories, which run the LINQ port.

3. **Fills in the test's parameters.** Each parameter (`IUserRepository`,
   `ICipherRepository`, ...) is resolved from that container by type. The same test
   method therefore runs once per database, against whichever implementation that
   database uses.

4. **Adds a skipped case, "Unconfigured", for every provider not configured.** That
   is where the "Skipped: 66" in the output below comes from: 22 tests x 3 unconfigured
   providers.

Backend:
- How it's configured
- What code path it exercises

**SQL Server** (Docker, `server/dev/docker-compose.yml` profile `mssql`)
- `BW_TEST_DATABASES__0__TYPE=SqlServer` + connection string
- The **real T-SQL function** + the Dapper repository. The thorough path.

**SQLite** (a local file)
- `...TYPE=Sqlite`, `Data Source=<file>`
- The LINQ port + EF repository. Quick, no Docker.

**MySQL** (Docker, profile `mysql`)
- `...TYPE=MySql` + connection string
- The LINQ port + EF repository, on a real server.

**Example output** of a clean run against SQL Server (real output, last lines). That's
12 generated + 10 hand-written tests; the 66 skipped are the same tests declared for
the three unconfigured providers:

```
$ cd server/test/Infrastructure.IntegrationTest
$ BW_TEST_DATABASES__0__TYPE=SqlServer BW_TEST_DATABASES__0__CONNECTIONSTRING="Server=localhost,1433;..." \
  dotnet test --filter "FullyQualifiedName~Vault.Repositories.AlloyCipherFixtureTests|FullyQualifiedName~Repositories.AlloyCipherAccessTests"
...
  Skipped Bit.Infrastructure.IntegrationTest.Vault.Repositories.AlloyCipherFixtureTests.canSeeExists_MatchesTvf [Sqlite] [1 ms]

Passed!  - Failed:     0, Passed:    22, Skipped:    66, Total:    88, Duration: 1 s - Infrastructure.IntegrationTest.dll (net10.0)
```


### 11.3 The hand-written comparison suite

`AlloyCipherAccessTests.cs` holds 10 written tests, using ordinary setup
helpers instead of fixtures. They cover mostly the same ground:

- `PersonalCipher_OwnerCanSee_Edit_Manage`, `PersonalCipher_OtherUserCannotSee`
- `OrgCipher_DirectReadOnlyGrant_CanSeeNotEdit`, `OrgCipher_DirectHidePasswordsGrant_CanSeeNotViewPassword`, `OrgCipher_DirectManageGrant_CanManage`
- `OrgCipher_RevokedMember_NotVisible`, `OrgCipher_DisabledOrg_NotVisible`, `OrgCipher_NotInAnyCollection_MemberCannotSee`
- `OrgCipher_GroupGrantOnly_CanSeeWithGroupPermissions`, `OrgCipher_DirectReadOnlyGrantPrecedesGroupWriteGrant`

A typical one:

```csharp
[DatabaseTheory, DatabaseData]
public async Task OrgCipher_RevokedMember_NotVisible(/* repositories */)
{
    var (user, org, orgUser) = await CreateUserOrgAndMember(..., OrganizationUserType.User,
                                                            status: OrganizationUserStatusType.Revoked);
    var (cipher, _) = await CreateOrgCipherInCollectionWithDirectGrant(org, orgUser, ...,
                                                            readOnly: false, hidePasswords: false, manage: false);
    var results = await cipherRepository.GetManyByUserIdAsync(user.Id);
    Assert.DoesNotContain(results, c => c.Id == cipher.Id);
}
```


**What Stage 5 accomplishes:** the model's predictions are checked against the real
Bitwarden code on a real database. A mismatch means either the model is wrong about
Bitwarden or Bitwarden's code has changed.




## 12. Side stage - Checking the model's security properties

**Code:** `scripts/alloy_checks.py` (shared runner) and `scripts/check_assertions.py` (CLI).

`predicates.als` contains the `assert` blocks but no `check` commands. The CLI can
only run commands that exist in the root module, and it silently does nothing for an
unknown command name. So `alloy_checks.py` writes a temporary wrapper module:

```alloy
module alloy_checks_wrapper
open predicates
check RevokedCannotSee for 4
check DisabledOrgBlocksAccess for 4
...                                  -- one line per assertion
```

#### How it works, step by step

1. `run_check_commands()` writes the wrapper to `alloy/static/_alloy_checks_wrapper.als`. It
   sits in the same folder as `predicates.als` (`alloy/static/`), so its `open
   predicates` line finds that file directly.

2. For each of the eight assertion names, `run_alloy_command()` empties a dedicated
   output folder (one per check, inside a temporary directory) and runs
   `java -jar scripts/lib/alloy6.jar exec -c <AssertionName> -t xml -q -f -o <folder>
   alloy/static/_alloy_checks_wrapper.als`.

3. The solver searches every world up to 4 atoms per type for one where the assertion's
   condition is **false**. If it finds one, it writes that world as
   `<AssertionName>-solution-0.xml`.

4. A solution file means a **counterexample was found**, so the assertion is
   `VIOLATED`. No solution file means it `holds` within scope 4. A non-zero exit code
   from Java raises an error. It is never reported as "holds".

5. The wrapper file is deleted in a `finally` block, even if a check crashes.

`check_assertions.py` prints one line per assertion, then a summary, and exits 1 if any
assertion is violated. The mutation harness calls the same `run_check_commands()` as
its Probe A (13.3), so the two can never disagree on how a check is run.

A violation's XML is an ordinary instance file, like the ones in Stage 1, so the Stage 2
parser can read it. It shows the exact database state that breaks the property. In
the 2026-10-05 run, the `RevokedCannotSee` counterexample has `User$0` holding three
memberships in `Organization$0`: `OrganizationUser$1` is `Confirmed`,
`OrganizationUser$2` and `OrganizationUser$3` are `Revoked` (a fourth membership,
`OrganizationUser$0`, is an `Invited` one with no user attached). The skolems name a
revoked one (`RevokedCannotSee_ou` -> `OrganizationUser$3`, `_u` -> `User$0`, `_c` ->
`Cipher$0`) as the reason the assertion applies, while the confirmed one still grants
access. That is the
situation explained in 14.4.

**Example output**

```
$ python3 scripts/check_assertions.py --repo-root .
  RevokedCannotSee: VIOLATED
  DisabledOrgBlocksAccess: holds
  UncollectedCipherInvisible: holds
  PersonalCipherIsPrivate: holds
  ReadOnlyPreventsEdit: holds
  NoAccessWithoutGrant: holds
  HidePasswordsPreventsViewPassword: holds
  NoManageGrantPreventsManage: holds

1 assertion(s) violated: RevokedCannotSee
```

The one violation is not a malfunction (14.4). The
script exits 1 because of it.

**What this side stage accomplishes:** it proves or refutes each security property
over *every* database state up to scope 4. This is a guarantee no finite test suite
gives. The flip side is that it verifies the *model*, not Bitwarden, which is why
Stages 1–5 exist.




## 13. The mutation-testing harness

**Code:** `scripts/mutation_test.py`.

### 13.1 The idea

A test suite is only as good as the bugs it catches. So plant a bug on purpose, a
**mutation**, re-run everything and see. A mutation that nothing
notices marks a blind spot. Each mutation is applied, measured and reverted one at a
time, after a clean **baseline** run with no mutation.

### 13.2 The catalog: 16 mutations

Each entry names a target file, a line anchor, an exact `find` text that must match
**exactly once** near that line, and its `replace` text.

ID: Category, Target, The planted bug

`S1` : `sql`
- `UserCipherDetails.sql:12`
- Invert the Confirmed-status gate (`= 2` -> `<> 2`)

`S2` : `sql`
- `UserCipherDetails.sql:41`
- Drop the org `Enabled = 1` kill switch

`S3` : `sql`
- `UserCipherDetails.sql:47`
- Drop the `CU.CollectionId IS NULL` guard on the group join

`L1` : `linq`
- `UserCipherDetailsQuery.cs:23`
- Match `Revoked` instead of `Confirmed`

`L2` : `linq`
- `UserCipherDetailsQuery.cs:27`
- Invert the `Enabled` join key

`L3` : `linq`
- `UserCipherDetailsQuery.cs:40`
- Remove the group-join null guard

`C1` : `dapper`
- `CipherRepository.cs:107`
- Swap the Edit/ViewPassword tie-break order

`A1` : `model`
- `static/predicates.als:67`
- Remove `groupGrant`'s parentheses (a real historical bug)

`A2` : `model`
- `static/predicates.als:203`
- Remove `canSee`'s org-enabled check

`A3` : `model`
- `static/predicates.als:217`
- Flip `canSee`'s admin-bypass role (`Owner + Admin` -> `Member + Custom`)

`A4` / `A5` / `A6` : `model`
- `static/predicates.als:257 / 297 / 335`
- The same flip in `canEdit` / `canViewPassword` / `canManage`

`W1` : `model`
- `static/predicates.als:144`
- Swap Edit/ViewPassword in `collectionBeats` (the model-side mirror of `C1`)

`W2` : `model`
- `static/predicates.als:164`
- Drop `winningCollection`'s "nothing beats it" clause

`W3` : `model`
- `static/predicates.als:113`
- Drop the `groupGrant` guard from `resolvedEdit`

Example entry, `C1`:

```
find:    .ThenByDescending(og => og.Edit)
         .ThenByDescending(og => og.ViewPassword).First())
replace: .ThenByDescending(og => og.ViewPassword)
         .ThenByDescending(og => og.Edit).First())
```

### 13.3 The two probes

For each mutation the harness measures two independent layers.

- **Probe A: formal assertions.** It runs the  checks against the (possibly
  mutated) model. This only applies to `model` mutations, since the others do not
  touch the model.

- **Probe B: C# tests.** It runs `dotnet test --filter FullyQualifiedName~Alloy
  --logger trx` in `server/`, parses the TRX results file, and splits the counts into
  **generated** (`AlloyCipherFixtureTests`) versus (`AlloyCipherAccessTests`).

For a `model` mutation, the pipeline (Stages 1–4) is first re-run on the mutated
model, and the new tests then run against the **unmutated** Bitwarden code. So a
generated test failing means "the buggy model now predicts something real Bitwarden
does not do". If a scenario turns UNSAT under the mutation, regeneration fails and
Probe B is recorded as `{"skipped": "pipeline_generation_failed"}`. That also counts
as a catch: the planted bug made a known-valid scenario impossible.

The hand-written tests do not come from the model, so a `model` mutation cannot
change them. They still run, against the same unmutated code, and always pass. For
model mutations the meaningful comparison is formal assertions versus generated
tests. The hand-written suite is the comparison point for real-code (`sql`, `linq`,
`dapper`) mutations.

### 13.4 How the database backends differ

`--db-type` selects the backend.

- **`sqlite`** (default): copies a `test.db` to a fresh scratch file for every
  run.

- **`sqlserver`**: uses one persistent `vault_dev` database in the Docker container.
  - `sql` mutations have to change the function *inside the running database*. The
    harness pushes `DROP FUNCTION ...; <mutated CREATE FUNCTION>` through `sqlcmd` in
    the container.
  - It then checks `OBJECT_ID('dbo.UserCipherDetails')` is not NULL, because
    `sqlcmd`'s exit code does not reliably report failure.
  - In a `finally` block it pushes the original back and checks again.
  - `dapper` mutations are just a C# edit plus a recompile.

- **`mysql`**: the code for a persistent MySQL database is there
  (`probe_b_dotnet_tests_mysql`, `--mysql-connection-string`), and only `linq` and
  `model` mutations would apply.
  The `--db-type` option only accepts `sqlite` and `sqlserver`, so `--db-type mysql`
  is rejected by the argument parser before anything runs. MySQL can still be used
  for a plain Stage 5 run.

`sql` and `dapper` mutations are refused under any `--db-type` other than
`sqlserver`. Otherwise they would silently test a code path that does not contain
the mutation.

### 13.5 How one run works, step by step

**Choosing what to run.** `--dry-run` validates the catalog and exits. `--run`
executes the mutations named in `--mutations`. If that flag is omitted, the default is
every catalog entry marked `runnable_here: True`: the `linq` and `model` ones, but not
`sql`/`dapper`, which need a SQL Server the harness can't assume exists. Before any
mutation, a **baseline** runs both probes on the unmutated code. That gives a control
to compare against, and confirms the starting point is clean.

**Applying a mutation (`apply_mutation`).**
1. Read the target file and split it into lines, keeping each line's exact line
   ending.
2. Take the window `line ... line + window − 1`
3. Count occurrences of `find` inside that window only. Anything other than exactly 1
   raises an error showing the expected and actual text. This catches a catalog that
   has drifted from the file.
4. Back up the file, replace `find` with `replace` once inside the window, splice the
   window back, and write the file.

**Running one mutation (`run_one_mutation`)**, by category:

Category :  Steps
`sql`:
- apply the mutation to `UserCipherDetails.sql` -> push the mutated function into the live database (below) -> Probe B on SQL Server -> restore the file -> push the original function back

`dapper`:
- apply the mutation to `CipherRepository.cs` -> Probe B on SQL Server (`dotnet test` recompiles with the change) -> restore the file

`linq`:
- apply the mutation to `UserCipherDetailsQuery.cs` -> Probe B on the chosen EF database -> restore the file

`model`:
- back up `alloy/instances/`, `alloy/fixtures/` and the generated `.cs`
    -> apply the mutation to `predicates.als` -> Probe A
    -> regenerate Stages 1–4 by running `alloy_to_fixture.py` as a subprocess
    -> if that fails (an UNSAT scenario), record `pipeline_generation_failed` and skip Probe B; otherwise Probe B -> restore everything

**Pushing a SQL function into the running database (`push_tvf_to_mssql`).** SQL Server
doesn't watch files, so editing `UserCipherDetails.sql` alone changes nothing. The
harness has to push the change into the database:
1. Write a batch file: `DROP FUNCTION [dbo].[UserCipherDetails]; GO <file contents>
   GO`. The drop is needed because the file is a plain `CREATE FUNCTION`, and SQL
   Server requires `CREATE FUNCTION` to start its own batch.
2. Make the file world-readable (`chmod 644`). Copy it into the container with
   `docker compose cp`.
3. Run it with the container's `sqlcmd` (`-C` trusts the container's self-signed
   certificate; the password comes from the `MSSQL_PASSWORD` environment variable).
4. Verify with `SELECT OBJECT_ID('dbo.UserCipherDetails')`. A NULL means the function
   is gone, and is reported as a failure even if `sqlcmd` exited 0.

**Probe B in detail.**
1. Set the `BW_TEST_DATABASES__0__...` environment variables for the chosen database.
   For SQL Server, `USEEF` is explicitly removed so the Dapper path is used.
2. For SQLite, first copy the golden `server/test/Infrastructure.IntegrationTest/test.db`
   (or the file given with `--db-source`) to a fresh scratch file, so runs can't affect
   each other.
3. Run `dotnet test test/Infrastructure.IntegrationTest --filter FullyQualifiedName~Alloy
   --logger trx` from `server/`. Results land in `.mutation_test_trx/`.
4. Parse the TRX file, the XML report `dotnet test` writes: every `UnitTestResult`
   element gives a test name and an outcome.
5. `summarize_probe_b()` keeps only `Passed`/`Failed` rows, which drops the "Unconfigured"
   skips. It sorts each row into **generated** or **hand-written** by whether the name
   contains `AlloyCipherFixtureTests` or `AlloyCipherAccessTests`, and counts. A failed
   test's name is shortened to just the method name for the report.

**Safety.** `server/` is not under this repository's git, so `git checkout` cannot undo
a mutation. A fresh `BackupManager` per mutation takes care of this:
- It records each file's exact bytes in memory before the first change, and copies
  whole folders to a temporary directory.
- `restore_all()` puts everything back in a `finally` block, so it runs even if a probe
  crashes.
- It also runs from an `atexit` hook and a SIGINT/SIGTERM handler, in case the script is
  interrupted.

Only a hard kill (`kill -9`) can bypass it.

At the end, the baseline and every mutation record are written to the `--out` JSON
file. A relative path is relative to the repository root.

### 13.6 Example outputs

**Dry run** validates every mutation's anchor without changing anything (real output):

```
$ python3 scripts/mutation_test.py --repo-root . --dry-run
Dry-run: validating 16 mutation find-strings...

  OK   S1   (sql) -- unique match at server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql:12
  OK   S2   (sql) -- unique match at server/src/Sql/dbo/Vault/Functions/UserCipherDetails.sql:41
  ...
  OK   C1   (dapper) -- unique match at server/src/Infrastructure.Dapper/Vault/Repositories/CipherRepository.cs:107-108
  OK   A1   (model) -- unique match at alloy/static/predicates.als:67
  ...
  OK   W1   (model) -- unique match at alloy/static/predicates.als:144-149
  OK   W2   (model) -- unique match at alloy/static/predicates.als:164-166
  OK   W3   (model) -- unique match at alloy/static/predicates.als:113

All mutations validated: every find-string matches exactly once within its line window.
```

**A real run** prints a per-mutation summary and writes a JSON file. Real output from
the full SQL Server pass of text 14 (the start, `C1`, `W1` and the end; `...` marks
omitted mutations). `W1` prints no test lines because its regeneration went UNSAT, so
Probe B was skipped:

```
$ export MSSQL_PASSWORD='...'
$ python3 scripts/mutation_test.py --repo-root . --run --db-type sqlserver \
    --mssql-connection-string "Server=localhost,1433;Database=vault_dev;..." \
    --mutations S1,S2,S3,C1,A1,A2,A3,A4,A5,A6,W1,W2,W3 --out alloy/docs/mutation-testing-full-sqlserver.json
DB type: sqlserver, persistent DB (no per-run scratch copy)
Running baseline (no mutation)...
    generated     12/12 passed
    hand-written  10/10 passed
...
=== Mutation C1 (dapper): Swap the Edit/ViewPassword tie-break priority in GetManyByUserIdAsync's OrderByDescending chain.
    generated     11/12 passed -- caught by: WinningRowDivergenceExists_MatchesTvf
    hand-written  10/10 passed
...
=== Mutation W1 (model): Swap the Edit/ViewPassword tie-break priority in collectionBeats

=== Mutation W2 (model): Drop winningCollection's maximality clause entirely, reverting to isGrantHoldingCollection alone, reintroduces the independent OR
    generated     12/12 passed
    hand-written  10/10 passed
...
Wrote /home/ph/projects/msocg/alloy/docs/mutation-testing-full-sqlserver.json
```

**The JSON record** for a model mutation (from the full run,
`alloy/docs/mutation-testing-full-sqlserver.json`, trimmed):

```json
{
  "id": "A5", "category": "model",
  "description": "Flip canViewPassword's admin-bypass role check (path 2) -- the canViewPassword analog of A3.",
  "probe_a": { "RevokedCannotSee": true, "DisabledOrgBlocksAccess": false, "...": false,
               "HidePasswordsPreventsViewPassword": true, "NoManageGrantPreventsManage": false },
  "fixture_regeneration": { "ok": true, "returncode": 0,
                            "stdout_tail": "...Wrote ...AlloyCipherFixtureTests.cs (12 test methods).\n" },
  "probe_b_summary": {
    "generated":    { "total": 12, "passed": 10, "failed": 2,
                      "failed_names": ["DirectGrantPrecedesGroupGrant_MatchesTvf", "HidePasswordsPathExists_MatchesTvf"] },
    "hand_written": { "total": 10, "passed": 10, "failed": 0, "failed_names": [] } }
}
```

In `probe_a`, `true` means violated.

**What the harness accomplishes:** it turns "are these tests any good?" into a
measured table. For each realistic bug it records whether the formal assertions, the
generated tests, the hand-written tests, several of them, or nothing noticed it.



## 14. Current results

Every number in this section comes from **one full run of the harness on the current
code**, made on 2026-10-05/06. It
was done in two passes, because the LINQ mutations can only be exercised on an
EF-backed database:

Pass, Mutations, Database, Duration, Raw results

1. `S1`–`S3`, `C1`, `A1`–`A6`, `W1`–`W3`
    SQL Server
    2 h 27 min
    `alloy/docs/mutation-testing-full-sqlserver.json`
2. `L1`–`L3`
    SQLite (a freshly migrated copy, via `--db-source`)
    8 min 45 s
    `alloy/docs/mutation-testing-full-linq-sqlite.json`

Both baselines (no mutation) passed 12/12 generated and 10/10 hand-written tests.

The TRX files in `.mutation_test_trx/` are overwritten by each run, so they now belong
to this run too.

### 14.1 a bug cought by the model-derived test

Mutation `C1` swaps two keys in the real repository's tie-break. Against real
SQL Server:

 `C1` Generated: **1 failed**: `WinningRowDivergenceExists_MatchesTvf` 

Under `C1`, the `Collection$0` row wins (higher ViewPassword), so the user gets
Edit = false and ViewPassword = true. The generated test's `Assert.True(details.Edit)`
fails. No hand-written test has two collections with conflicting grants, so the whole
hand-written suite is blind to this class of bug.

This scenario exists only because the model had to state the winning-row rule
precisely. An early version of the model assumed the simpler OR-per-flag rule.
Reading `CipherRepository.cs` showed that was wrong. The generated test then
*confirmed against a real database* that Bitwarden uses winning-row semantics.

### 14.2 The full kill matrix

A cell shows how many tests **failed** out of the suite size, with the failing tests
named when there are three or fewer. "n/a" means the layer cannot see that kind of
mutation by construction: Probe A only runs for model mutations, and
hand-written tests cannot be affected by a model mutation (they passed 10/10 in every
model-mutation run, as expected).

 ID -- Formal assertions (Probe A) -- Generated tests -- Hand-written tests -- Database 

`S1` status gate:
    - n/a
    - 8 / 12
    - 6 / 10
`S2` kill switch:
    - n/a
    - 1 / 12 (`DisabledOrgScenario`)
    - 1 / 10 (`OrgCipher_DisabledOrg_NotVisible`)
    - SQL Server
`S3` group guard:
    - n/a
    - 0 / 12
    - 0 / 10
    - SQL Server
`C1` tie-break:
    - n/a
    - 1 / 12 (`WinningRowDivergenceExists`)
    - 0 / 10
    - SQL Server
`L1` status gate:
    - n/a
    - 8 / 12
    - 6 / 10
    - SQLite
`L2` kill switch:
    - n/a
    - 8 / 12
    - 6 / 10
    - SQLite
`L3` group guard:
    - n/a 
    - 0 / 12
    - 0 / 10
    - SQLite
`A1` groupGrant parens:
    - `NoAccessWithoutGrant` violated
    - 1 / 12 (`NoAccessWithoutGrantScenario`)
    - n/a
    - SQL Server
`A2` model kill switch:
    - `DisabledOrgBlocksAccess` violated
    - 3 / 12 (`DirectGrantPrecedesGroupGrant`, `DisabledOrgScenario`, `canSeeExists`)
    - n/a 
    - SQL Server
`A3` canSee bypass:
    - `UncollectedCipherInvisible` violated
    - 0 / 12
    - n/a
    - SQL Server
`A4` canEdit bypass:
    - `ReadOnlyPreventsEdit` violated
    - 1 / 12 (`ReadOnlyPathExists`)
    - n/a
    - SQL Server
`A5` canViewPassword bypass:
    - `HidePasswordsPreventsViewPassword` violated
    - 2 / 12 (`DirectGrantPrecedesGroupGrant`, `HidePasswordsPathExists`)
    - n/a
    - SQL Server
`A6` canManage bypass
    - `NoManageGrantPreventsManage` violated
    - 1 / 12 (`DirectGrantPrecedesGroupGrant`)
    - n/a
    - SQL Server
`W1` model tie-break:
    - none
    - caught: `WinningRowDivergenceExists` becomes **UNSAT**
    - n/a
    - SQL Server
`W2` winningCollection maximality:
    - none
    - 0 / 12
    - n/a
    - SQL Server
`W3` resolvedEdit guard:
    - none
    - 0 / 12
    - n/a
    - SQL Server

`RevokedCannotSee` reported violated in every run, including both baselines. That is
the standing finding in 14.4, not a catch, so it is left out of the assertion column.

### 14.3 What the matrix says

- **The layers are complementary, not redundant.**
  - Real-code bugs (`S`, `L`, `C`) can only be seen by the C# tests.
  - All six `A` mutations are caught by exactly one formal assertion each. Five of
    them also make at least one generated test fail; `A3` is caught by its assertion
    alone.
  - The `W` mutations are caught by no assertion. `W1` is caught only because its
    purpose-built scenario becomes impossible, and `W2`/`W3` are not caught at all
- **On real-code bugs, the generated suite catches everything the hand-written suite
  does, and more.**
  - Both catch `S1`, `S2`, `L1` and `L2`. The generated suite has as many or more
    failing tests each time (8 vs 6, 1 vs 1, 8 vs 6, 8 vs 6).
  - Neither catches `S3` or `L3`.
  - `C1` is caught only by the generated suite.
- **Neither C# suite can test the admin bypass.** Both call `GetManyByUserIdAsync`,
  which does not apply it, so admin-bypass bugs in the real code would go
  unnoticed by both. The `A3`–`A6` rows are bugs in the *model's* copy of the bypass,
  which is why the assertions can catch them.
- **`S3`/`L3` are structural no-ops, not missed bugs.** `COALESCE(CU.x, CG.x, 0)`
  already prefers the direct grant, and the LINQ port re-checks `cu == null` in its
  projection and `WHERE`. So removing the join guard changes no output. The guard is
  redundant in both implementations.
- **`A5`/`A6` would be invisible to every assertion** without
  `HidePasswordsPreventsViewPassword` and `NoManageGrantPreventsManage`. Each is caught
  by exactly its own assertion.

### 14.4 The live finding: `RevokedCannotSee` is violated

On the unmutated model, `check RevokedCannotSee` finds a counterexample. Here is how:

- A user holds **two** memberships in the same organization, one `Revoked` and one
  `Confirmed`.
- The confirmed one grants access.
- So a "revoked" user still sees the cipher.

Nothing in the model forbids two memberships per (user, organization), and the real
database schema does not forbid it either: there is no unique constraint at the
database or EF level. The invite code path guards against duplicates, but not every
creation path has been checked. Adding a uniqueness fact to make the check pass would
claim a guarantee Bitwarden does not structurally have. So the model deliberately
leaves this open, and it is reported as a real, unresolved question.

### 14.5 Open gaps in the model's own coverage

- **`W2`:** `winningRow`'s cross-row comparison (`rowBeats`) re-derives the correct
  winner on its own, so breaking `winningCollection` has no observable effect.
  Protection is redundant, but a regression in `winningCollection` alone would go
  unnoticed. No assertion tests its contract in isolation.
- **`W3`:** the scenario meant to exercise this path (`DirectGrantPrecedesGroupGrant`)
  can be satisfied by a solver witness that routes around the mutated disjunct.



## 15. Known limitations and open questions

**What the model does not cover**

- **The admin bypass cannot be tested through these suites.** It lives in
  `GetCipherPermissionsForUserQuery`, and both suites call `GetManyByUserIdAsync`.
  Only the formal assertions reason about it.
- **Unmodeled behaviour:**
  - The `Custom` role with `EditAnyCollection` also bypasses.
  - `CanAccessUnassignedCiphers` gives admins access to uncollected ciphers without
    checking the org flag. So `UncollectedCipherInvisible`'s "only exception" is
    narrower than reality.
  - `UserCollectionDetails.sql` (collection-level permissions) is not modeled at all.
  - Soft delete, provider admins, `DefaultUserCollection` and `LimitItemDeletion` are
    out of scope by design.

**Keeping the model in sync**

- **No automatic sync with the schema.** The model is hand-written, and nothing
  detects when Bitwarden's SQL changes.

**Test generation**

- **Solver output is not guaranteed to be stable across environments.** Nothing pins
  the Alloy/SAT-solver version, so a different setup could produce a different but
  equally valid instance. The *meaning* of each scenario would stay the same, but the
  exact rows might not. With the current JAR, re-solving reproduces the committed XML
  exactly.
- **One fallback test subject is heuristic.** `PersonalPrivacyScenario` relies on a
  derivation rule rather than a skolem.
- **The `ReadOnlyPathExists` run command has a duplicated line**

**Environment**

- **`server/` is outside git.** It has to be recreated from upstream Bitwarden plus
  the committed `server-files/`. The copies there are kept in sync by hand:
  after regenerating tests or editing the hand-written files inside `server/`, copy
  them back into `server-files/`, or a fresh clone will get stale versions.
- **The committed SQLite `test.db` is schema-stale.** It lacks later migrations, so
  every test fails on it with `table User has no column named LastApiKeyRotationDate`.
  The harness's earlier LINQ runs failed for exactly this reason. Use a freshly
  migrated copy and pass it with `--db-source`.
- **`--db-type mysql` is rejected** by the harness's argument parser, although the
  MySQL code path exists.4).
- **Test data accumulates.** Tests never delete their rows. Unique GUIDs and run tags
  keep this harmless.
- **Nothing runs in CI.** Every check is run by hand.



## 16. Command cheat-sheet

You need Java (the run here used OpenJDK 27-ea), Python 3 with `pyyaml`, the .NET 10
SDK, Docker, the Bitwarden checkout in `server/` and the Alloy 6.2.0 JAR at
`scripts/lib/alloy6.jar`. Neither of the last two is committed; 5.1 shows how to get
them. There is no separate README in this repository, so the one-time database setup
is included here:

```bash
# One-time: SQL Server container and schema (password is in server/dev/.env)
cd server/dev && docker compose --profile mssql up -d && cd ../..
cd server && dotnet run --project util/MsSqlMigratorUtility -- \
  "Server=localhost,1433;Database=vault_dev;User Id=sa;Password=...;TrustServerCertificate=True;" && cd ..

# One-time: a migrated SQLite file (the committed test.db is schema-stale, see 15)
cd server/util/SqliteMigrations
dotnet ef database update --connection "Data Source=/path/to/alloy.db" \
  -- --GlobalSettings:Sqlite:ConnectionString="Data Source=/path/to/alloy.db"
cd ../../..

# Check the model's 8 security properties
python3 scripts/check_assertions.py --repo-root .

# Stages 1-4: re-solve all 12 scenarios, rewrite instances/, fixtures/, and the generated .cs
python3 scripts/alloy_to_fixture.py --repo-root .            # --skip-alloy reuses existing XML; -v shows subject choice

# Stage 5 against real SQL Server (container from server/dev: docker compose --profile mssql up -d)
cd server/test/Infrastructure.IntegrationTest
BW_TEST_DATABASES__0__TYPE=SqlServer \
BW_TEST_DATABASES__0__CONNECTIONSTRING="Server=localhost,1433;Database=vault_dev;User Id=sa;Password=...;TrustServerCertificate=True;" \
dotnet test --filter "FullyQualifiedName~Vault.Repositories.AlloyCipherFixtureTests|FullyQualifiedName~Repositories.AlloyCipherAccessTests"

# Mutation testing
python3 scripts/mutation_test.py --repo-root . --dry-run                     # validate the catalog
python3 scripts/mutation_test.py --repo-root . --run --mutations L1,L2,L3 \
  --db-source /path/to/alloy.db --out alloy/docs/mutation-testing-full-linq-sqlite.json   # LINQ mutations, SQLite
export MSSQL_PASSWORD='...'
python3 scripts/mutation_test.py --repo-root . --run --db-type sqlserver \
  --mssql-connection-string "Server=localhost,1433;Database=vault_dev;..." --mutations S1,S2,S3,C1 --out /tmp/r.json
```
