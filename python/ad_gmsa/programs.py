import subprocess

import ad_gmsa.utils
import ad_gmsa.config_file
from ad_gmsa.config_file import config


def get_highest_kvno(keytab_file):
    highest_kvno_res = subprocess.run([
            config.highest_kvno_prog,
            keytab_file
        ],
        capture_output = True
    )

    ad_gmsa.utils.raise_subprocess_error('highest_kvno', highest_kvno_res)

    highest_kvno_res_str = highest_kvno_res.stdout.decode()

    return int(highest_kvno_res_str) if len(highest_kvno_res_str) > 0 else None

def add_keytab_entry(keytab_file, principal, kvno, password, enctypes,
    service_names = [],
    is_machine_account = False,
    is_hex_password_input = False,
    salt = '',
    pass_password_as_hex = False):

    add_keytab_entry_args = [
        config.add_keytab_entry_prog,
    ]

    if is_machine_account:
        add_keytab_entry_args.append('--is-machine-account')
    
    if is_hex_password_input or pass_password_as_hex:
        add_keytab_entry_args.append('--is-hex-password-input')

    if salt is not None and len(salt) > 0:
        add_keytab_entry_args.extend(['--salt', salt])

    add_keytab_entry_args.extend([
        keytab_file,
        principal,
        str(kvno),
        ','.join(enctypes),
    ])

    if service_names is not None and len(service_names) > 0:
        add_keytab_entry_args.extend(service_names)

    process_stdin = password if not pass_password_as_hex else password.encode().hex()
    add_keytab_entry_res = subprocess.run(args = add_keytab_entry_args,
        capture_output = True,
        input = process_stdin.encode()
    )

    ad_gmsa.utils.raise_subprocess_error('add_keytab_entry', add_keytab_entry_res)

def cleanup_keytab(keytab_file, key_versions_to_keep):
    cleanup_keytab_res = subprocess.run([
            config.cleanup_keytab_prog,
            keytab_file,
            key_versions_to_keep,
        ],
        capture_output = True
    )

    ad_gmsa.utils.raise_subprocess_error('cleanup_keytab', cleanup_keytab_res)

