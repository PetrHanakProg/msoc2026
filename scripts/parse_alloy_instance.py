"""
parse_alloy_instance.py: Parse an Alloy instance XML file into a structured dict.

The Alloy Analyzer writes instance XML when a run command finds a satisfying
assignment. This module reads that XML and returns a normalized dict that
instance_to_fixture.py can translate into a C# test fixture.
"""

import xml.etree.ElementTree as ET
from pathlib import Path


# Sig labels that appear in every Alloy instance no matterthe model.
_BUILTIN_SIG_LABELS = {
    "univ", "Int", "seq/Int", "String", "none",
}

# Atom labels for builtin Alloy singletons. Exclude from field processing
# because they do not correspond to model entities.
_BUILTIN_ATOM_LABELS = {
    "univ", "Int", "seq/Int", "String", "none",
}


def _strip_module_prefix(label: str) -> str:
    """
    Remove the 'this/' or 'static/' module prefix from a sig label.
    Examples:
        'this/User'              → 'User'
    """
    return label.split("/")[-1]


def parse_instance(xml_path: str | Path) -> dict:
    """
    Parse an Alloy instance XML file and return a structured dict.

    Args:
        xml_path: Path to the instance XML file written by AlloyRunner.java.

    Returns:
        A dict with keys:
            command (str): The run command label, or "" if not found.
            atoms (dict[str, str]): Maps atom label to sig type name.
                example {"User$0": "User", "Confirmed": "OrgUserStatus", ...}
            fields (dict[str, list[tuple[str, str]]]): Maps field label to
                list of (source_atom, target_atom) tuples.
                example {"enabled": [("Organization$0", "True")], ...}

    Raises:
        FileNotFoundError: If xml_path does not exist.
        ET.ParseError: If the XML is malformed.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Find the <instance> element wherever it is.
    if root.tag == "instance":
        instance_elem = root
    else:
        instance_elem = root.find(".//instance")
        if instance_elem is None:
            raise ValueError(f"No <instance> element found in {xml_path}")

    # Extract the command label (the run command name used to generate this instance).
    command = instance_elem.get("command", "")

    # Build atoms dict: label to sig type
    # Each <sig> element lists the atoms that belong to it.
    atoms: dict[str, str] = {}
    for sig_elem in instance_elem.findall("sig"):
        raw_label = sig_elem.get("label", "")
        sig_type = _strip_module_prefix(raw_label)

        # Skip built-in sigs
        if sig_type in _BUILTIN_SIG_LABELS or raw_label in _BUILTIN_SIG_LABELS:
            continue

        for atom_elem in sig_elem.findall("atom"):
            raw_atom_label = atom_elem.get("label", "")
            atom_label = _strip_module_prefix(raw_atom_label)
            if atom_label and atom_label not in _BUILTIN_ATOM_LABELS:
                # If an atom appears under multiple sigs (inheritance), the most
                # specific sig wins. For our model, sigs don't use
                # inheritance except for enums
                # where we want the concrete atom name mapped to the abstract sig.
                if atom_label not in atoms:
                    atoms[atom_label] = sig_type

    skolems: dict[str, str] = {}
    for skolem_elem in instance_elem.findall("skolem"):
        raw_label = skolem_elem.get("label", "").lstrip("$")
        if not raw_label:
            continue
        tuples = skolem_elem.findall("tuple")
        if tuples:
            atom_elems = tuples[0].findall("atom")
            if atom_elems:
                atom = _strip_module_prefix(atom_elems[0].get("label", ""))
                if atom:
                    skolems[raw_label] = atom

    # Build fields dict: label to a list of (source, target) tuples
    # Each <field> element contains <tuple> children, each with two <atom> children.
    fields: dict[str, list[tuple[str, str]]] = {}
    for field_elem in instance_elem.findall("field"):
        field_label = field_elem.get("label", "")
        if not field_label:
            continue

        tuples: list[tuple[str, str]] = []
        for tuple_elem in field_elem.findall("tuple"):
            atom_elems = tuple_elem.findall("atom")
            if len(atom_elems) == 2:
                source = _strip_module_prefix(atom_elems[0].get("label", ""))
                target = _strip_module_prefix(atom_elems[1].get("label", ""))
                if source and target:
                    tuples.append((source, target))
            #higher-arity relations are not used in this model; skip.

        if tuples:
            if field_label in fields:
                fields[field_label].extend(tuples)
            else:
                fields[field_label] = tuples

    return {
        "command": command,
        "atoms": atoms,
        "fields": fields,
        "skolems": skolems,
    }


def atom_type(parsed: dict, atom_label: str) -> str | None:
    """Return the sig type for a given atom label, or None if unknown."""
    return parsed["atoms"].get(atom_label)


def atoms_of_type(parsed: dict, sig_type: str) -> list[str]:
    """Return all atom labels whose sig type matches sig_type."""
    return [label for label, t in parsed["atoms"].items() if t == sig_type]


def field_targets(parsed: dict, field_label: str, source_atom: str) -> list[str]:
    """Return all target atoms for a given (field_label, source_atom) pair."""
    return [
        target
        for src, target in parsed["fields"].get(field_label, [])
        if src == source_atom
    ]


def field_source(parsed: dict, field_label: str, target_atom: str) -> list[str]:
    """Return all source atoms for a given (field_label, target_atom) pair."""
    return [
        src
        for src, target in parsed["fields"].get(field_label, [])
        if target == target_atom
    ]


if __name__ == "__main__":
    import sys, json

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <instance.xml>")
        sys.exit(1)

    result = parse_instance(sys.argv[1])
    print(f"Command: {result['command']}")
    print(f"Atoms ({len(result['atoms'])}):")
    for label, typ in sorted(result["atoms"].items()):
        print(f"  {label!r:30s} → {typ}")
    print(f"Fields ({len(result['fields'])}):")
    for fname, tuples in sorted(result["fields"].items()):
        for src, tgt in tuples:
            print(f"  {fname!r:25s}: {src} → {tgt}")
