#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
#include <iostream>

#include <krb5.h>

#include "krb_objects.hpp"


bool starts_with(const std::string &str, const std::string &prefix) {

	return str.rfind(prefix, 0) == 0;
}

std::string to_lower_case(const std::string &str) {
	
	std::string copy(str.size(), '\0');

	std::transform(
		str.begin(),
		str.end(),
		copy.begin(),
		[](unsigned char c) -> unsigned char {
			return std::tolower(c);
		}
	);

	return copy;
}

std::string to_upper_case(const std::string &str) {
	
	std::string copy(str.size(), '\0');

	std::transform(
		str.begin(),
		str.end(),
		copy.begin(),
		[](unsigned char c) -> unsigned char {
			return std::toupper(c);
		}
	);

	return copy;
}

int parse_hex_char(unsigned char c) {

	if (std::isdigit(c)) {
		return c - '0';
	} else {
		return 10 + (std::tolower(c) - 'a');
	}
}

std::string hex_decode(const std::string &input) {

	size_t output_len = input.size() / 2;
	std::string data;
	for (size_t i = 0; i < output_len; i++) {

		data.push_back(static_cast<char>(
			parse_hex_char(input.at(i * 2)) << 4 |
			parse_hex_char(input.at(i * 2 + 1))
		));
	}

	return data;
}

std::string hex_encode(const std::string &input) {

	std::string encoded;

	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < input.size(); i++) {

		encoded.push_back(hex_chars[input.at(i) & 0xf0 >> 4]);
		encoded.push_back(hex_chars[input.at(i) & 0xf]);
	}

	return encoded;
}

void show_usage() {

	std::cerr << "usage: <program> [ --is-machine-account ] [ --salt <salt> ] [ --is-hex-password ] <keytab file> <principal> <kvno> <comma-separated enctypes> [ <service name>... ]" << std::endl;
}

int main(int argc, char *argv[]) {

	bool is_machine_account = false;
	bool is_hex_password_input = false;
	std::string salt;

	int current_arg_index = 1;
	while (current_arg_index < argc) {

		std::string current_arg = argv[current_arg_index];

		if (current_arg == "--is-machine-account") {
			is_machine_account = true;
			current_arg_index++;
		
		} else if (current_arg == "--is-hex-password-input") {
			is_hex_password_input = true;
			current_arg_index++;

		} else if (current_arg == "--salt") {
			current_arg_index++;
			if (current_arg_index < argc) {
				salt = argv[current_arg_index];
				current_arg_index++;
			}

		} else if (current_arg == "--")  {
			current_arg_index++;
			break;

		} else if (!starts_with(current_arg, "--")) {
			break;

		} else {
			std::cerr << "unknown option '" << current_arg << "'" << std::endl;
			show_usage();
			return 1;
		}
	}

	int remaining_args = argc - current_arg_index;
	if (remaining_args < 4) {

		std::cerr << "not enough arguments" << std::endl;
		show_usage();
		return 1;
	}

	std::string keytab_file_name;
	std::string principal_string;
	std::string enctypes_string;
	int kvno;

	keytab_file_name = argv[current_arg_index];
	current_arg_index++;

	principal_string = argv[current_arg_index];
	current_arg_index++;

	kvno = std::stoi(argv[current_arg_index]);
	current_arg_index++;

	enctypes_string = argv[current_arg_index];
	current_arg_index++;

	std::vector<std::string> service_names;
	if (current_arg_index < argc) {

		while (current_arg_index < argc) {

			service_names.push_back(std::string(argv[current_arg_index]));
			current_arg_index++;
		}
	}

	std::string password;
	std::getline(std::cin, password);
	if (is_hex_password_input) {
		password = hex_decode(password);
	}

	std::cout << "is_machine_account: " << is_machine_account << std::endl;
	std::cout << "salt: " << salt << std::endl;
	std::cout << "is_hex_password_input: " << is_hex_password_input << std::endl;

	std::cout << std::endl;

	std::cout << "keytab_file_name: " << keytab_file_name << std::endl;
	std::cout << "principal_string: " << principal_string << std::endl;
	std::cout << "kvno: " << kvno << std::endl;
	std::cout << "enctypes_string: " << enctypes_string << std::endl;

	if (service_names.size() > 0) {
		std::cout << std::endl;

		std::cout << service_names.size() << " service names:" << std::endl;

		for (auto it = service_names.begin(); it != service_names.end(); it++) {
			std::cout << "\t" << *it << std::endl;
		}
	}

	std::vector<krb5_enctype> enctypes_to_use;
	{
		std::string::size_type last_pos = 0;
		while (last_pos != std::string::npos && last_pos < enctypes_string.size()) {

			auto next_pos = enctypes_string.find(",", last_pos);

			std::string current;
			if (next_pos == std::string::npos) {
				current = enctypes_string.substr(last_pos);
				last_pos = std::string::npos;
			} else {
				current = enctypes_string.substr(last_pos, next_pos - last_pos);
				last_pos = next_pos + 1;
			}

			krb5_enctype enctype;
			if (current == "ENCTYPE_AES256_CTS_HMAC_SHA1_96") {
				enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
			} else if (current == "ENCTYPE_AES128_CTS_HMAC_SHA1_96") {
				enctype = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
			} else {
				std::cerr << "unknown enctype '" << current << "'" << std::endl;
				std::cerr << "supported enctypes: ENCTYPE_AES128_CTS_HMAC_SHA1_96, ENCTYPE_AES256_CTS_HMAC_SHA1_96" << std::endl;
				return 1;
			}
			enctypes_to_use.push_back(enctype);
		}
	}

	KrbContext context;
	KrbPrincipal principal = context.parse_name(principal_string);
	if (salt.size() < 1) {

		std::string realm = principal.get_realm();
		std::string principal_name = principal.get_name();

		if (is_machine_account) {
			std::string name_without_suffix = principal_name;
			if (name_without_suffix.back() == '$') {
				name_without_suffix.pop_back();
			}
			salt = to_upper_case(realm) + "host" + to_lower_case(name_without_suffix) + "." + to_lower_case(realm);

		} else {
			salt = to_upper_case(realm) + principal_name;
		}
	}

	std::cout << "salt: " << salt << std::endl;

	std::vector<KrbKeyblock> keyblocks;
	for (auto it = enctypes_to_use.begin() ; it != enctypes_to_use.end() ; it++) {

		keyblocks.push_back(context.string_to_key(*it, password, salt));
	}

	KrbKeytab keytab = context.resolve_keytab(keytab_file_name);
	for (auto it = keyblocks.begin() ; it != keyblocks.end() ; it++) {

		keytab.add_entry(principal, *it, kvno);
	}

	if (service_names.size() > 0) {

		for (auto it_service_name = service_names.begin(); it_service_name != service_names.end(); it_service_name++) {
			for (auto it_keyblock = keyblocks.begin(); it_keyblock != keyblocks.end() ; it_keyblock++) {

				KrbPrincipal service_principal = context.parse_name(*it_service_name);
				keytab.add_entry(service_principal, *it_keyblock, kvno);
			}
		}
	}

	return 0;
}

