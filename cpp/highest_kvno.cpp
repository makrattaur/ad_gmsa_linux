#include <algorithm>
#include <vector>
#include <iostream>

#include "krb_objects.hpp"


int main(int argc, char *argv[]) {

	if (argc < 2) {
		std::cerr << "not enough arguments" << std::endl;
		std::cerr << "usage: <program> <keytab file>" << std::endl;
		return 1;
	}

	KrbContext context;

	KrbKeytab keytab = context.resolve_keytab(argv[1]);

	krb5_kvno highest_kvno = 0;
	bool has_entry = false;

	KrbKeytabCursor cursor = keytab.get_cursor();
	while (cursor.has_next()) {

		KrbKeytabEntry entry = cursor.get();
		highest_kvno = std::max(entry.get_kvno(), highest_kvno);
		has_entry = true;
	}

	if (has_entry) {
		std::cout << highest_kvno << std::endl;
	}

	return 0;
}

