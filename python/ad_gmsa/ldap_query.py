import base64
from collections import namedtuple
from datetime import (datetime, timedelta)
import io
import subprocess

import ad_gmsa.password_blob
import ad_gmsa.utils
import ad_gmsa.config_file
from ad_gmsa.config_file import config


__all__ = [ 'GmsaAccount', 'get_gmsa_accounts_info' ]


GmsaAccount = namedtuple('GmsaAccount', 'sam_account_name next_change next_change_date service_names kvno password')


def parse_simple_ldif(string_stream):

    entries = []
    
    entry_dn = None
    current_entry = {}

    for line in string_stream:

        line = line.strip()
        if line == '' or line.startswith('#'):
            continue

        if line.startswith('dn:'):
            if entry_dn is not None:
                entries.append((entry_dn, current_entry))

                current_entry = {}
            
            entry_dn = line[ (line.index(' ') + 1) : ]
            if line.startswith('dn::'):
                entry_dn = base64.b64decode(entry_dn)

        else:
            
            sep_index = line.index(':')
            current_property = line[ : sep_index ]

            current_property_value = None
            if line[sep_index + 1] == ' ':
                current_property_value= line[(sep_index + 2) : ]
            else:
                # handle 'prop:: <base64>'
                current_property_value = base64.b64decode(line[(sep_index + 3) : ])

            if current_property in current_entry:
                current_entry[current_property].append(current_property_value)
            else:
                current_entry[current_property] = [ current_property_value ]

    if entry_dn is not None:
        entries.append((entry_dn, current_entry))

    return entries

def get_gmsa_accounts_info(ldap_uri, search_base, sam_account_names):

    query_part = ''.join(f'(sAMAccountName={account})' for account in sam_account_names)

    query_res = subprocess.run([
            config.ldapsearch_prog,
            '-o', 'ldif-wrap=no',
            '-LLL',
            '-H', ldap_uri,
            '-b', search_base,
            f'(|{query_part})',
            'msDS-ManagedPassword', 'msDS-KeyVersionNumber', 'sAMAccountName', 'servicePrincipalName'
        ],
        capture_output = True
    )

    ad_gmsa.utils.raise_subprocess_error('ldapsearch', query_res)

    query_result_ldif = parse_simple_ldif(io.StringIO(query_res.stdout.decode()))

    gmsa_accounts_info = []
    for dn, attributes in query_result_ldif:

        if 'msDS-ManagedPassword' not in attributes:
            continue

        decoded_blob = ad_gmsa.password_blob.decode_msds_managed_pw_blob(attributes['msDS-ManagedPassword'][0])

        now = datetime.now()

        # see https://markgamache.blogspot.com/2016/12/gmsas-are-little-bit-weird.html for a example.

        # the current password is still valid 10 minutes from this date but it is now
        # in the old password field and kvno is not increased.
        password_expires = timedelta(microseconds = decoded_blob.unchanged_password_interval / 1000)
        password_expires_date = now + password_expires

        # both the new password and the old password are accepted 5 minutes after this
        # date and kvno has increased.
        next_query = timedelta(microseconds = decoded_blob.query_password_interval / 1000)
        next_query_date = now + next_query

        gmsa_accounts_info.append(GmsaAccount(
            sam_account_name = attributes['sAMAccountName'][0],
            next_change = next_query,
            next_change_date = next_query_date,
            service_names = attributes['servicePrincipalName'] if 'servicePrincipalName' in attributes else [],
            kvno = int(attributes['msDS-KeyVersionNumber'][0]),
            # try to return the correct password that is associated with the right kvno.
            password = decoded_blob.current_password if next_query > password_expires else decoded_blob.previous_password,
        ))

    return gmsa_accounts_info





