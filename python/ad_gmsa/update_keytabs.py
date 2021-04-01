#!/usr/bin/env python3

from datetime import timedelta
import os.path
import subprocess
import sys
import time

import ad_gmsa.programs
import ad_gmsa.ldap_query
import ad_gmsa.config_file
from ad_gmsa.config_file import config


def process_gmsa_account(account_info):
    keytab_file_name = f'{account_info.sam_account_name}.keytab'
    keytab_path = os.path.join(config.keytab_dir, keytab_file_name)

    need_insert = False

    if os.path.isfile(keytab_file_name):

        keytab_kvno = ad_gmsa.programs.get_highest_kvno(keytab_path)
        if keytab_kvno is not None:
            if account_info.kvno > keytab_kvno:
                print('ldap kvno changed, need insert')
                need_insert = True
            else:
                print('kvno ok')
        else:
            print('no highest kvno, need insert')
            need_insert = True
    else:
        print('no keytab, need insert')
        need_insert = True

    if need_insert:

        is_machine_account = account_info.sam_account_name.endswith('$')

        ad_gmsa.programs.add_keytab_entry(
            keytab_path,
            principal = f'{account_info.sam_account_name}@{config.realm}',
            kvno = account_info.kvno,
            password = account_info.password.encode('utf_8').hex(),
            enctypes = config.enctypes,
            service_names = account_info.service_names if len(account_info.service_names) > 0 else [],
            is_hex_password_input = True,
            is_machine_account = is_machine_account,
        )

        ad_gmsa.programs.cleanup_keytab(
            keytab_path,
            config.key_versions_to_keep
        )

def main():

    ad_gmsa.config_file.load_config()

    while True:
        gmsa_accounts_info = ad_gmsa.ldap_query.get_gmsa_accounts_info(config.ldap_uri, config.search_base, config.sam_account_names)

        one_account_failed = False
        for account_info in gmsa_accounts_info:

            print(f'process account {account_info.sam_account_name}')
            print(f'account {account_info.sam_account_name} will change in {account_info.next_change}')

            try:
                process_gmsa_account(account_info)
                print(f'processed account {account_info.sam_account_name}')
            except:
                one_account_failed = True
                print(f'failed to process account {account_info.sam_account_name}: {sys.exc_info()}')
        
        closest_change_time = min(account.next_change for account in gmsa_accounts_info)
        next_query = None
        if closest_change_time > timedelta(hours = 7):
            next_query = timedelta(hours = 7)
        elif closest_change_time > timedelta(hours = 1):
            next_query = timedelta(hours = 1)
        elif closest_change_time > timedelta(minutes = 10):
            next_query = timedelta(minutes = 10)
        elif closest_change_time > timedelta(minutes = 5):
            next_query = timedelta(minutes = 5)
        else:
            next_query = timedelta(minutes = 1)

        if one_account_failed and next_query > timedelta(minutes = 5):
            next_query = timedelta(minutes = 5)

        print(closest_change_time)
        print(next_query)

        time.sleep(next_query.total_seconds())


if __name__ == "__main__":
    main()


