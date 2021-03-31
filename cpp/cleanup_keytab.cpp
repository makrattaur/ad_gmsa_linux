#include <algorithm>
#include <vector>
#include <iostream>

#include "krb_objects.hpp"


int main(int argc, char *argv[]) {

	if (argc < 3) {
		std::cerr << "not enough arguments" << std::endl;
		std::cerr << "usage: <program> <keytab file> <number of versions to keep>" << std::endl;
		return 1;
	}

	unsigned int versions_to_keep_count = std::stoi(argv[2]);

	KrbContext context;

	KrbKeytab keytab = context.resolve_keytab(argv[1]);

	std::vector<KrbKeytabEntry> entries;
	{
		KrbKeytabCursor cursor = keytab.get_cursor();
		while (cursor.has_next()) {

			entries.push_back(cursor.get());
		}
	}

	krb5_kvno highest_kvno = 0;
	for (auto it = entries.begin(); it != entries.end(); it++) {

		highest_kvno = std::max(it->get_kvno(), highest_kvno);
	}

	if (highest_kvno < versions_to_keep_count) {
		return 0;
	}

	krb5_kvno delete_kvno = highest_kvno - versions_to_keep_count;
	for (auto it = entries.begin(); it != entries.end(); it++) {

		if (it->get_kvno() <= delete_kvno) {
			keytab.delete_entry(*it);
		}
	}

	return 0;
}

