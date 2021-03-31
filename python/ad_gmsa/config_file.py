import configparser
import os
from ad_gmsa import core_config


class Config:

    def _load(self, conf_parser):

        self.ldapsearch_prog = conf_parser.get('exec_locations', 'ldapsearch', fallback = core_config.LDAPSEARCH_PROG)
        self.highest_kvno_prog = conf_parser.get('exec_locations', 'highest_kvno', fallback = core_config.HIGHEST_KVNO_PROG)
        self.add_keytab_entry_prog = conf_parser.get('exec_locations', 'add_keytab_entry', fallback = core_config.ADD_KEYTAB_ENTRY_PROG)
        self.cleanup_keytab_prog = conf_parser.get('exec_locations', 'cleanup_keytab', fallback = core_config.CLEANUP_KEYTAB_PROG)

        self.realm = conf_parser['config']['realm']
        self.ldap_uri = conf_parser['config']['ldap_uri']
        self.search_base = conf_parser['config']['search_base']
        self.keytab_dir = conf_parser.get('config', 'keytab_dir', fallback = '.')
        self.key_versions_to_keep = conf_parser.getint('config', 'key_versions_to_keep', fallback = 3)

        self.sam_account_names = []
        accounts_section = conf_parser.items('accounts')
        for account, _ in accounts_section:
            self.sam_account_names.append(account)

        valid_enctypes_set = set(['ENCTYPE_AES256_CTS_HMAC_SHA1_96', 'ENCTYPE_AES128_CTS_HMAC_SHA1_96'])

        self.enctypes = []
        enctypes_string = conf_parser['config']['enctypes']
        enctypes = enctypes_string.split(',')
        for enctype in enctypes:

            enctype = enctype.strip()
            if enctype not in valid_enctypes_set:
                raise ValueError(f'Invalid enctype {enctype}')

            self.enctypes.append(enctype)


config = Config()


def load_config():
    conf_parser = configparser.ConfigParser(
        allow_no_value = True,
        empty_lines_in_values = False,
        interpolation = None
    )

    with open(core_config.CONFIG_FILE) as main_file:
        conf_parser.read_file(main_file)

    if 'include_dir' in conf_parser['config']:
        include_dir = conf_parser['config']['include_dir']

        if os.path.isdir(include_dir):
            for file in os.listdir(include_dir):
                if file.endswith('.ini'):
                    conf_parser.read(file)

    config._load(conf_parser)


