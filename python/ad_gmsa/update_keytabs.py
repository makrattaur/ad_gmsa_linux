#!/usr/bin/env python3

from datetime import (datetime, timedelta)
import os.path
import subprocess
import sys
import time
import logging

import ad_gmsa.programs
import ad_gmsa.ldap_query
import ad_gmsa.config_file
from ad_gmsa.config_file import config


logger = logging.getLogger(__name__)


def process_gmsa_account(account_info):
    keytab_file_name = f'{account_info.sam_account_name}.keytab'
    keytab_path = os.path.join(config.keytab_dir, keytab_file_name)

    need_insert = False

    if os.path.isfile(keytab_path):

        keytab_kvno = ad_gmsa.programs.get_highest_kvno(keytab_path)
        if keytab_kvno is not None:
            if account_info.kvno > keytab_kvno:
                logger.info(f'[{account_info.sam_account_name}] ldap kvno changed, need insert')
                need_insert = True
            else:
                logger.info(f'[{account_info.sam_account_name}] kvno ok')
        else:
            logger.info(f'[{account_info.sam_account_name}] no highest kvno, need insert')
            need_insert = True
    else:
        logger.info(f'[{account_info.sam_account_name}] no keytab, need insert')
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

    return need_insert

def main():

    logging.basicConfig(
        level = logging.INFO,
        format = '%(asctime)s %(levelname)s %(name)s: %(message)s',
    )

    ad_gmsa.config_file.load_config()

    active_password_changes = set()

    while True:
        gmsa_accounts_info = ad_gmsa.ldap_query.get_gmsa_accounts_info(config.ldap_uri, config.search_base, config.sam_account_names)

        if len(gmsa_accounts_info) < 1:
            logger.warn(f'no accounts to monitor')
            break

        one_account_failed = False
        for account_info in gmsa_accounts_info:

            logger.info(f'process account {account_info.sam_account_name}')
            logger.info(f'account {account_info.sam_account_name} will change in {account_info.next_change} (on {datetime.now() + account_info.next_change})')

            if account_info.sam_account_name not in active_password_changes:
                if account_info.next_change < timedelta(minutes = 5):
                    logger.info(f'account {account_info.sam_account_name} in password change phase')
                    active_password_changes.add(account_info.sam_account_name)

            has_updated_keytab = False
            try:
                has_updated_keytab = process_gmsa_account(account_info)
                logger.info(f'processed account {account_info.sam_account_name}')
            except:
                one_account_failed = True
                logger.error(f'failed to process account {account_info.sam_account_name}', exc_info = sys.exc_info())

            if account_info.sam_account_name in active_password_changes and has_updated_keytab:
                logger.info(f'account {account_info.sam_account_name} exited password change phase')
                active_password_changes.remove(account_info.sam_account_name)

        closest_change_time = min(account.next_change for account in gmsa_accounts_info)
        next_query = None
        if closest_change_time > timedelta(hours = 8):
            next_query = timedelta(hours = 7)
        elif closest_change_time > timedelta(hours = 2):
            next_query = timedelta(hours = 1)
        elif closest_change_time > timedelta(hours = 1):
            next_query = timedelta(minutes = 10)
        elif closest_change_time > timedelta(minutes = 15):
            next_query = timedelta(minutes = 7)
        else:
            next_query = timedelta(minutes = 1)

        if len(active_password_changes) > 0:
            next_query = timedelta(minutes = 1)

        if one_account_failed and next_query > timedelta(minutes = 5):
            next_query = timedelta(minutes = 5)

        logger.info(f'closest change time: {closest_change_time} (on {datetime.now() + closest_change_time})')
        logger.info(f'one account failed: {one_account_failed}, active password change count: {len(active_password_changes)}')
        logger.info(f'wait for: {next_query} (on {datetime.now() + next_query})')

        time.sleep(next_query.total_seconds())


if __name__ == "__main__":
    main()


