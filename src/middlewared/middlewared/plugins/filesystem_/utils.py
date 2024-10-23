from middlewared.utils.filesystem.acl import (
    FS_ACL_Type,
    NFS4ACE_Flag,
    NFS4ACE_FlagSimple,
)


def __ace_is_inherited_nfs4(ace):
    if ace['flags'].get('BASIC'):
        return False

    return ace['flags'].get(NFS4ACE_Flag.INHERITED, False)


def canonicalize_nfs4_acl(theacl):
    """
    Order NFS4 ACEs according to MS guidelines:
    1) Deny ACEs that apply to the object itself (NOINHERIT)
    2) Allow ACEs that apply to the object itself (NOINHERIT)
    3) Deny ACEs that apply to a subobject of the object (INHERIT)
    4) Allow ACEs that apply to a subobject of the object (INHERIT)

    See http://docs.microsoft.com/en-us/windows/desktop/secauthz/order-of-aces-in-a-dacl
    Logic is simplified here because we do not determine depth from which ACLs are inherited.
    """
    acltype = FS_ACL_Type(theacl['acltype'])
    if acltype != FS_ACL_Type.NFS4:
        raise ValueError(f'{acltype}: ACL canonicalization not supported for ACL type')

    out = []
    acl_groups = {
        "deny_noinherit": [],
        "deny_inherit": [],
        "allow_noinherit": [],
        "allow_inherit": [],
    }

    for ace in theacl:
        key = f'{ace.get("type", "ALLOW").lower()}_{"inherit" if __ace_is_inherited_nfs4(ace) else "noinherit"}'
        acl_groups[key].append(ace)

    for g in acl_groups.values():
        out.extend(g)

    return out


def __calculate_inherited_posix1e(theacl, isdir):
    inherited = []
    for entry in theacl['acl']:
        if entry['default'] is False:
            continue

        # add access entry
        inherited.append(entry.copy() | {'default': False})

        if isdir:
            # add default entry
            inherited.append(entry)

    return inherited


def __calculate_inherited_nfs4(theacl, isdir):
    inherited = []
    for entry in theacl['acl']:
        if not (flags := entry.get('flags', {}).copy()):
            continue

        if (basic := flags.get('BASIC')) == NFS4ACE_FlagSimple.NOINHERIT:
            continue
        elif basic == NFS4ACE_FlagSimple.INHERIT:
            flags[NFS4ACE_Flag.INHERITED] = True
            inherited.append(entry)
            continue
        elif not flags.get(NFS4ACE_Flag.FILE_INHERIT, False) and not flags.get(NFS4ACE_Flag.DIRECTORY_INHERIT, False):
            # Entry has no inherit flags
            continue
        elif not isdir and not flags.get(NFS4ACE_Flag.FILE_INHERIT):
            # File and this entry doesn't inherit on files
            continue

        if isdir:
            if not flags.get(NFS4ACE_Flag.DIRECTORY_INHERIT, False):
                if flags[NFS4ACE_Flag.NO_PROPAGATE_INHERIT]:
                    # doesn't apply to this dir and shouldn't apply to contents.
                    continue

                # This is a directory ACL and we have entry that only applies to files.
                flags[NFS4ACE_Flag.INHERIT_ONLY] = True
            elif flags.get(NFS4ACE_Flag.INHERIT_ONLY, False):
                flags[NFS4ACE_Flag.INHERIT_ONLY] = False
            elif flags.get(NFS4ACE_Flag.NO_PROPAGATE_INHERIT):
                flags[NFS4ACE_Flag.DIRECTORY_INHERIT] = False
                flags[NFS4ACE_Flag.FILE_INHERIT] = False
                flags[NFS4ACE_Flag.NO_PROPAGATE_INHERIT] = False
        else:
            flags[NFS4ACE_Flag.DIRECTORY_INHERIT] = False
            flags[NFS4ACE_Flag.FILE_INHERIT] = False
            flags[NFS4ACE_Flag.NO_PROPAGATE_INHERIT] = False
            flags[NFS4ACE_Flag.INHERIT_ONLY] = False

        inherited.append({
            'tag': entry['tag'],
            'id': entry['id'],
            'type': entry['type'],
            'perms': entry['perms'],
            'flags': flags | {NFS4ACE_Flag.INHERITED: True}
        })

    return inherited


def calculate_inherited_acl(theacl, isdir=True):
    acltype = FS_ACL_Type(theacl['acltype'])

    match acltype:
        case FS_ACL_Type.POSIX1E:
            return __calculate_inherited_posix1e(theacl, isdir)

        case FS_ACL_Type.NFS4:
            return __calculate_inherited_nfs4(theacl, isdir)

        case FS_ACL_Type.DISABLED:
            ValueError('ACL is disabled')

        case _:
            TypeError(f'{acltype}: unknown ACL type')
