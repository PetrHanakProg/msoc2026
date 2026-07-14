"""
instance_to_fixture.py: Translate a parsed Alloy instance into a C# test fixture JSON.

Takes the structured dict from parse_alloy_instance.parse_instance() and produces
a fixture JSON describing the database entities to create and the expected permission
outcomes to assert.

Translation pipeline:
1. Identify all atoms and their sig types from the parsed instance.
2. For each atom, collect its field values by scanning the fields dict for tuples
   where that atom is the source.
3. Resolve Alloy field labels to fixture JSON keys using pipeline_config.yaml
   field_map section.
4. Resolve enum atom labels to integer values using
   the enum_values section of pipeline_config.yaml.
5. Apply test-subject derivation rules from alloy_test_expectations.yaml to identify
   which User and Cipher atoms the test should exercise.
6. Return a fixture dict that can be serialized to JSON and embedded in the C# test.

Fixture JSON format:
    {
      "name": "<run command name>",
      "expected": {
        "can_see": true/false/null,
        "can_edit": true/false/null,
        "can_view_password": true/false/null,
        "can_manage": true/false/null
      },
      "test_subject": {
        "user": "<alloy atom label for the test user>",
        "cipher": "<alloy atom label for the test cipher>"
      },
      "entities": {
        "users":              [{"alloy_id": "..."}],
        "organizations":      [{"alloy_id": "...", "enabled": bool, "allow_admin_access": bool}],
        "ciphers":            [{"alloy_id": "...", "owner_org": "...|null", "owner_user": "...|null"}],
        "collections":        [{"alloy_id": "...", "org_id": "..."}],
        "collection_ciphers": [{"collection_id": "...", "cipher_id": "..."}],
        "organization_users": [{"alloy_id": "...", "user_id": "...", "org_id": "...",
                                "status": int, "type": int, "has_key": bool}],
        "groups":             [{"alloy_id": "...", "org_id": "..."}],
        "group_users":        [{"group_id": "...", "org_user_id": "..."}],
        "collection_users":   [{"collection_id": "...", "org_user_id": "...",
                                "read_only": bool, "hide_passwords": bool, "manage": bool}],
        "collection_groups":  [{"collection_id": "...", "group_id": "...",
                                "read_only": bool, "hide_passwords": bool, "manage": bool}]
      }
    }
"""

from __future__ import annotations

import yaml
from pathlib import Path

import parse_alloy_instance as pai


def load_config(repo_root: str | Path) -> dict:
    """Load pipeline_config.yaml from the scripts/ directory."""
    config_path = Path(repo_root) / "scripts" / "pipeline_config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


def _find_user_with_org_access(parsed: dict) -> str | None:
    """
    Find the User atom that has a confirmed OrganizationUser with at least one
    collection grant (direct via CollectionUser) covering a cipher in a collection.

    This is the user for most positive scenarios (can_see: true).
    If multiple candidates exist, return the first found.

    !: If this returns the wrong atom, the test will silently test the wrong
    scenario. After first run, manually verify the returned atom against the XML.
    """
    # Build index: orgUser memberUser
    ou_to_user: dict[str, str] = {}
    for ou_atom in pai.atoms_of_type(parsed, "OrganizationUser"):
        users = pai.field_targets(parsed, "memberUser", ou_atom)
        if users:
            ou_to_user[ou_atom] = users[0]

    # Build index: CollectionUser cuOrgUser (to find which OU has a direct grant)
    cu_to_ou: dict[str, str] = {}
    for cu_atom in pai.atoms_of_type(parsed, "CollectionUser"):
        ous = pai.field_targets(parsed, "cuOrgUser", cu_atom)
        if ous:
            cu_to_ou[cu_atom] = ous[0]

    def _is_confirmed(ou_atom: str) -> bool:
        # Status atoms are enum one sigs: label is "Confirmed$0" after prefix strip.
        return any(
            pai.atom_type(parsed, s) == "Confirmed"
            for s in pai.field_targets(parsed, "status", ou_atom)
        )

    # Find an OU that is Confirmed and has a direct CollectionUser grant
    confirmed_ous_with_grant: set[str] = set()
    for cu_atom, ou_atom in cu_to_ou.items():
        if _is_confirmed(ou_atom):
            confirmed_ous_with_grant.add(ou_atom)

    # Also check group grants (CollectionGroup via Group.members)
    # Build: OU groups it belongs to
    ou_groups: dict[str, list[str]] = {}
    for grp_atom in pai.atoms_of_type(parsed, "Group"):
        members = pai.field_targets(parsed, "members", grp_atom)
        for ou_atom in members:
            ou_groups.setdefault(ou_atom, []).append(grp_atom)

    # Build: Group CollectionGroup atoms for that group
    grp_to_cg: dict[str, list[str]] = {}
    for cg_atom in pai.atoms_of_type(parsed, "CollectionGroup"):
        grps = pai.field_targets(parsed, "cgGroup", cg_atom)
        for grp in grps:
            grp_to_cg.setdefault(grp, []).append(cg_atom)

    for ou_atom in pai.atoms_of_type(parsed, "OrganizationUser"):
        if not _is_confirmed(ou_atom):
            continue
        # Check group grant path
        for grp in ou_groups.get(ou_atom, []):
            if grp_to_cg.get(grp):
                confirmed_ous_with_grant.add(ou_atom)

    # Map the first qualifying OU back to its User
    for ou_atom in confirmed_ous_with_grant:
        user = ou_to_user.get(ou_atom)
        if user:
            return user

    # Fallback: return any user with an OrganizationUser record
    for ou_atom, user in ou_to_user.items():
        return user

    return None


def _find_user_not_cipher_owner(parsed: dict) -> str | None:
    """
    Find a User atom that does NOT appear as the target of any owner tuple.

    Used for PersonalPrivacyScenario: the user who should NOT be able to see
    a personal cipher owned by a different user.
    """
    # All users that appear as owner of some cipher
    owner_users: set[str] = set()
    for src, tgt in parsed["fields"].get("owner", []):
        # owner tuples: (Cipher$N, User$M) or (Cipher$N, Organization$M)
        if pai.atom_type(parsed, tgt) == "User":
            owner_users.add(tgt)

    for user_atom in pai.atoms_of_type(parsed, "User"):
        if user_atom not in owner_users:
            return user_atom

    return None


def _find_cipher_in_collection(parsed: dict) -> str | None:
    """Find a Cipher atom that appears in at least one Collection.ciphers tuple."""
    ciphers_in_col: set[str] = set()
    for src, tgt in parsed["fields"].get("ciphers", []):
        ciphers_in_col.add(tgt)

    for cipher_atom in pai.atoms_of_type(parsed, "Cipher"):
        if cipher_atom in ciphers_in_col:
            return cipher_atom
    return None


def _find_cipher_not_in_collection(parsed: dict) -> str | None:
    """Find a Cipher atom that appears in NO Collection.ciphers tuple."""
    ciphers_in_col: set[str] = set()
    for src, tgt in parsed["fields"].get("ciphers", []):
        ciphers_in_col.add(tgt)

    for cipher_atom in pai.atoms_of_type(parsed, "Cipher"):
        if cipher_atom not in ciphers_in_col:
            return cipher_atom
    return None


def _find_personal_cipher(parsed: dict) -> str | None:
    """Find a Cipher whose owner is a User atom (personal cipher, not org cipher)."""
    for src, tgt in parsed["fields"].get("owner", []):
        if pai.atom_type(parsed, src) == "Cipher" and pai.atom_type(parsed, tgt) == "User":
            return src
    return None


# Maps rule name (from alloy_test_expectations.yaml) to the implementing function.
_DERIVATION_RULES: dict[str, callable] = {
    "find_user_with_org_access":   _find_user_with_org_access,
    "find_user_not_cipher_owner":  _find_user_not_cipher_owner,
    "find_cipher_in_collection":   _find_cipher_in_collection,
    "find_cipher_not_in_collection": _find_cipher_not_in_collection,
    "find_personal_cipher":        _find_personal_cipher,
}


# Entity builders
#
def _bare_enum_name(atom: str) -> str:
    """
    Strip the '$N' suffix that Alloy appends to one sig atoms.

    Enum atoms are declared as one sig Confirmed extends OrgUserStatus {} so on
    The Alloy analyzer labels their atoms as 'Confirmed$0', 'True$0', etc.
    The pipeline_config.yaml enum_values dict uses bare names ('Confirmed', 'True').
    """
    return atom.split("$")[0] if "$" in atom else atom


def _resolve_bool(atom: str, enum_values: dict) -> bool:
    """Resolve a Bool atom ('True$0' or 'False$0') to a Python bool."""
    val = enum_values.get(_bare_enum_name(atom))
    if val is None:
        raise ValueError(f"Unknown Bool atom: {atom!r}")
    return bool(val)


def _resolve_enum(atom: str, enum_values: dict) -> int:
    """Resolve an enum atom label (e.g. 'Confirmed$0') to its integer value."""
    val = enum_values.get(_bare_enum_name(atom))
    if val is None:
        raise ValueError(f"Unknown enum atom: {atom!r} — add it to pipeline_config.yaml enum_values")
    return int(val)


def _build_users(parsed: dict) -> list[dict]:
    return [{"alloy_id": a} for a in pai.atoms_of_type(parsed, "User")]


def _build_organizations(parsed: dict, enum_values: dict) -> list[dict]:
    result = []
    for atom in pai.atoms_of_type(parsed, "Organization"):
        enabled_atoms = pai.field_targets(parsed, "enabled", atom)
        admin_atoms = pai.field_targets(parsed, "allowAdminAccess", atom)
        result.append({
            "alloy_id": atom,
            # Default True if field is absent (unlikely in a valid instance but safe)
            "enabled": _resolve_bool(enabled_atoms[0], enum_values) if enabled_atoms else True,
            "allow_admin_access": _resolve_bool(admin_atoms[0], enum_values) if admin_atoms else False,
        })
    return result


def _build_ciphers(parsed: dict) -> list[dict]:
    result = []
    for atom in pai.atoms_of_type(parsed, "Cipher"):
        owner_targets = pai.field_targets(parsed, "owner", atom)
        owner_org = None
        owner_user = None
        if owner_targets:
            owner = owner_targets[0]
            if pai.atom_type(parsed, owner) == "Organization":
                owner_org = owner
            elif pai.atom_type(parsed, owner) == "User":
                owner_user = owner
        result.append({
            "alloy_id": atom,
            "owner_org": owner_org,
            "owner_user": owner_user,
        })
    return result


def _build_collections(parsed: dict) -> list[dict]:
    result = []
    for atom in pai.atoms_of_type(parsed, "Collection"):
        org_targets = pai.field_targets(parsed, "org", atom)
        result.append({
            "alloy_id": atom,
            "org_id": org_targets[0] if org_targets else None,
        })
    return result


def _build_collection_ciphers(parsed: dict) -> list[dict]:
    """Expand Collection.ciphers junction relation into CollectionCipher rows."""
    result = []
    for col_atom, cipher_atom in parsed["fields"].get("ciphers", []):
        result.append({
            "collection_id": col_atom,
            "cipher_id": cipher_atom,
        })
    return result


def _build_organization_users(parsed: dict, enum_values: dict) -> list[dict]:
    result = []
    for atom in pai.atoms_of_type(parsed, "OrganizationUser"):
        org_targets  = pai.field_targets(parsed, "memberOrg",  atom)
        user_targets = pai.field_targets(parsed, "memberUser", atom)
        status_atoms = pai.field_targets(parsed, "status",     atom)
        role_atoms   = pai.field_targets(parsed, "role",       atom)
        key_targets  = pai.field_targets(parsed, "key",        atom)

        result.append({
            "alloy_id":  atom,
            "org_id":    org_targets[0]  if org_targets  else None,
            "user_id":   user_targets[0] if user_targets else None,
            "status":    _resolve_enum(status_atoms[0], enum_values) if status_atoms else 0,
            "type":      _resolve_enum(role_atoms[0],   enum_values) if role_atoms   else 0,
            # Key presence (has_key: true) means status=Confirmed; value is a sentinel.
            "has_key":   bool(key_targets),
        })
    return result


def _build_groups(parsed: dict) -> list[dict]:
    result = []
    for atom in pai.atoms_of_type(parsed, "Group"):
        org_targets = pai.field_targets(parsed, "groupOrg", atom)
        result.append({
            "alloy_id": atom,
            "org_id": org_targets[0] if org_targets else None,
        })
    return result


def _build_group_users(parsed: dict) -> list[dict]:
    """Expand Group.members junction relation into GroupUser rows."""
    result = []
    for grp_atom, ou_atom in parsed["fields"].get("members", []):
        result.append({
            "group_id":    grp_atom,
            "org_user_id": ou_atom,
        })
    return result


def _build_collection_users(parsed: dict, enum_values: dict) -> list[dict]:
    result = []
    for atom in pai.atoms_of_type(parsed, "CollectionUser"):
        col_targets  = pai.field_targets(parsed, "cuCollection",  atom)
        ou_targets   = pai.field_targets(parsed, "cuOrgUser",     atom)
        ro_atoms     = pai.field_targets(parsed, "readOnly",      atom)
        hp_atoms     = pai.field_targets(parsed, "hidePasswords", atom)
        mgr_atoms    = pai.field_targets(parsed, "manage",        atom)
        result.append({
            "collection_id": col_targets[0] if col_targets else None,
            "org_user_id":   ou_targets[0]  if ou_targets  else None,
            "read_only":     _resolve_bool(ro_atoms[0],  enum_values) if ro_atoms  else False,
            "hide_passwords":_resolve_bool(hp_atoms[0],  enum_values) if hp_atoms  else False,
            "manage":        _resolve_bool(mgr_atoms[0], enum_values) if mgr_atoms else False,
        })
    return result


def _build_collection_groups(parsed: dict, enum_values: dict) -> list[dict]:
    result = []
    for atom in pai.atoms_of_type(parsed, "CollectionGroup"):
        col_targets  = pai.field_targets(parsed, "cgCollection",  atom)
        grp_targets  = pai.field_targets(parsed, "cgGroup",       atom)
        ro_atoms     = pai.field_targets(parsed, "readOnly",      atom)
        hp_atoms     = pai.field_targets(parsed, "hidePasswords", atom)
        mgr_atoms    = pai.field_targets(parsed, "manage",        atom)
        result.append({
            "collection_id": col_targets[0] if col_targets else None,
            "group_id":      grp_targets[0] if grp_targets else None,
            "read_only":     _resolve_bool(ro_atoms[0],  enum_values) if ro_atoms  else False,
            "hide_passwords":_resolve_bool(hp_atoms[0],  enum_values) if hp_atoms  else False,
            "manage":        _resolve_bool(mgr_atoms[0], enum_values) if mgr_atoms else False,
        })
    return result


# Main entry point

def build_fixture(
    parsed: dict,
    run_name: str,
    expectation: dict,
    config: dict,
    *,
    verbose: bool = False,
) -> dict:
    """
    Build a fixture dict from a parsed Alloy instance and expectation config.

    Args:
        parsed: Output of parse_alloy_instance.parse_instance().
        run_name:Name of the Alloy run command (used as fixture name).
        expectation: One entry from alloy_test_expectations.yaml for this run.
            Keys:test_user (rule name), test_cipher (rule name), expected (dict).
        config:Loaded pipeline_config.yaml dict.
        verbose: If True, print chosen test-subject atoms for manual verification.

    Returns:
        A fixture dict ready to be serialised to JSON.
    """
    enum_values: dict = config.get("enum_values", {})

    # Resolve test subjects using derivation rules.
    user_rule   = expectation.get("test_user",   "find_user_with_org_access")
    cipher_rule = expectation.get("test_cipher", "find_cipher_in_collection")

    user_fn   = _DERIVATION_RULES.get(user_rule)
    cipher_fn = _DERIVATION_RULES.get(cipher_rule)

    if user_fn is None:
        raise ValueError(f"Unknown test_user derivation rule: {user_rule!r}")
    if cipher_fn is None:
        raise ValueError(f"Unknown test_cipher derivation rule: {cipher_rule!r}")

    test_user   = user_fn(parsed)
    test_cipher = cipher_fn(parsed)

    if verbose:
        print(f"  test_user   ({user_rule}):   {test_user}")
        print(f"  test_cipher ({cipher_rule}): {test_cipher}")

    if test_user is None:
        raise ValueError(f"Could not derive test_user with rule {user_rule!r} for run '{run_name}'")
    if test_cipher is None:
        raise ValueError(f"Could not derive test_cipher with rule {cipher_rule!r} for run '{run_name}'")

    # Build expected dict — only include keys where value is not None.
    raw_expected = expectation.get("expected", {})
    expected = {k: v for k, v in raw_expected.items() if v is not None}

    return {
        "name": run_name,
        "alloy_command": parsed.get("command", ""),
        "expected": expected,
        "test_subject": {
            "user":   test_user,
            "cipher": test_cipher,
        },
        "entities": {
            "users":              _build_users(parsed),
            "organizations":      _build_organizations(parsed, enum_values),
            "ciphers":            _build_ciphers(parsed),
            "collections":        _build_collections(parsed),
            "collection_ciphers": _build_collection_ciphers(parsed),
            "organization_users": _build_organization_users(parsed, enum_values),
            "groups":             _build_groups(parsed),
            "group_users":        _build_group_users(parsed),
            "collection_users":   _build_collection_users(parsed, enum_values),
            "collection_groups":  _build_collection_groups(parsed, enum_values),
        },
    }
