#include "krb_objects.hpp"

#include <stdexcept>
#include <utility>
#include <iostream>


krb5_data string_to_krb_data(const std::string &data);
std::string krb_data_to_string(krb5_data &krb_data);
std::string get_error_message(krb5_context context, krb5_error_code code);


KrbContext::KrbContext()
	: m_context(nullptr) {

	krb5_error_code ret = krb5_init_context(&m_context);
	if (ret) {
		throw std::runtime_error("krb5_init_context: " + std::to_string(ret));
	}
}

KrbContext::KrbContext(KrbContext &&other)
	: m_context(other.m_context) {

	other.m_context = nullptr;
}

KrbContext::~KrbContext() {

	if (m_context) {
		krb5_free_context(m_context);
		m_context = nullptr;
	}
}

KrbKeytab KrbContext::resolve_keytab(const std::string &name) {

	krb5_keytab keytab = nullptr;
	
	krb5_error_code ret = krb5_kt_resolve(m_context, name.c_str(), &keytab);
	if (ret) {
		throw std::runtime_error("krb5_kt_resolve (" + std::to_string(ret) + "): " + get_error_message(*this, ret));
	}

	return KrbKeytab(*this, keytab);
}

KrbPrincipal KrbContext::parse_name(const std::string &name) {

	krb5_principal principal = nullptr;
	
	krb5_error_code ret = krb5_parse_name(m_context, name.c_str(), &principal);
	if (ret) {
		throw std::runtime_error("krb5_parse_name (" + std::to_string(ret) + "): " + get_error_message(*this, ret));
	}

	return KrbPrincipal(*this, principal);
}

KrbKeyblock KrbContext::string_to_key(krb5_enctype enctype, const std::string &string, const std::string &salt) {

	krb5_data string_data = string_to_krb_data(string);;
	krb5_data salt_data = string_to_krb_data(salt);

	krb5_keyblock keyblock = {0};

	krb5_error_code ret = krb5_c_string_to_key(m_context, enctype, &string_data, &salt_data, &keyblock);
	if (ret) {
		krb5_free_keyblock_contents(m_context, &keyblock);
		throw std::runtime_error("krb5_c_string_to_key (" + std::to_string(ret) + "): " + get_error_message(*this, ret));
	}

	return KrbKeyblock(*this, keyblock);
}


KrbPrincipal::KrbPrincipal(KrbContext &context, krb5_principal principal)
	: m_context(context),
	m_principal(principal) {

}

KrbPrincipal::KrbPrincipal(KrbPrincipal &&other)
	: m_context(other.m_context),
	m_principal(other.m_principal) {

	other.m_principal = nullptr;
}

KrbPrincipal::~KrbPrincipal() {

	if (m_principal) {
		krb5_free_principal(m_context, m_principal);
		m_principal = nullptr;
	}
}

std::string KrbPrincipal::get_realm() {

	return krb_data_to_string(m_principal->realm);
}

std::string KrbPrincipal::get_name() {

	return krb_data_to_string(*(m_principal->data));
}


KrbKeyblock::KrbKeyblock(KrbContext &context, krb5_keyblock keyblock)
	: m_context(context),
	m_freed(false),
	m_keyblock(keyblock) {

}

KrbKeyblock::KrbKeyblock(KrbKeyblock &&other)
	: m_context(other.m_context),
	m_freed(false),
	m_keyblock(other.m_keyblock) {

	other.m_freed = true;
}

KrbKeyblock::~KrbKeyblock() {

	if (!m_freed) {
		krb5_free_keyblock_contents(m_context, &m_keyblock);
		m_keyblock = {0};
		m_freed = true;
	}
}


KrbKeytab::KrbKeytab(KrbContext &context, krb5_keytab keytab)
	: m_context(context),
	m_keytab(keytab) {

}

KrbKeytab::KrbKeytab(KrbKeytab &&other)
	: m_context(other.m_context),
	m_keytab(other.m_keytab) {

	other.m_keytab = nullptr;
}

KrbKeytab::~KrbKeytab() {

	if (m_keytab) {
		krb5_kt_close(m_context, m_keytab);
		m_keytab = nullptr;
	}
}

void KrbKeytab::add_entry(KrbPrincipal &principal, KrbKeyblock &keyblock, krb5_kvno vno) {

	krb5_keytab_entry entry = {0};
	entry.principal = principal;
	entry.key = keyblock;
	entry.vno = vno;

	krb5_error_code ret = krb5_kt_add_entry(m_context, m_keytab, &entry);
	if (ret) {
		throw std::runtime_error("krb5_kt_add_entry (" + std::to_string(ret) + "): " + get_error_message(m_context, ret));
	}
}

void KrbKeytab::delete_entry(KrbKeytabEntry &entry) {

	krb5_error_code ret = krb5_kt_remove_entry(m_context, m_keytab, entry.get_ptr());
	if (ret) {
		throw std::runtime_error("krb5_kt_remove_entry (" + std::to_string(ret) + "): " + get_error_message(m_context, ret));
	}
}

KrbKeytabCursor KrbKeytab::get_cursor() {

	krb5_kt_cursor cursor;
	
	krb5_error_code ret = krb5_kt_start_seq_get(m_context, m_keytab, &cursor);
	if (ret) {
		krb5_kt_end_seq_get(m_context, m_keytab, &cursor);
		throw std::runtime_error("krb5_kt_remove_entry (" + std::to_string(ret) + "): " + get_error_message(m_context, ret));
	}

	return KrbKeytabCursor(m_context, *this, cursor);
}


KrbKeytabEntry::KrbKeytabEntry(KrbContext &context)
	: m_context(context),
	m_freed(true),
	m_entry{0} {

}

KrbKeytabEntry::KrbKeytabEntry(KrbContext &context, krb5_keytab_entry entry)
	: m_context(context),
	m_freed(false),
	m_entry(entry) {

}

KrbKeytabEntry::KrbKeytabEntry(KrbKeytabEntry &&other)
	: m_context(other.m_context),
	m_freed(false),
	m_entry(other.m_entry) {

	other.m_freed = true;
}

KrbKeytabEntry::~KrbKeytabEntry() {

	free_entry();
}

KrbKeytabEntry &KrbKeytabEntry::operator= (KrbKeytabEntry &&other) {

	free_entry();

	m_context = other.m_context;
	m_freed = other.m_freed;
	m_entry = other.m_entry;

	other.m_freed = true;

	return *this;
}

bool KrbKeytabEntry::is_freed() {
	return m_freed;
}

krb5_keytab_entry * KrbKeytabEntry::get_ptr() {
	return &m_entry;
}

void KrbKeytabEntry::free_entry() {

	if (!m_freed) {
		krb5_free_keytab_entry_contents(m_context.get(), &m_entry);
		m_entry = {0};
		m_freed = true;
	}
}

std::string KrbKeytabEntry::get_principal_name() {

	char *name_ptr = nullptr;
	
	krb5_error_code ret = krb5_unparse_name(m_context.get(), m_entry.principal, &name_ptr);
	if (ret) {

		krb5_free_unparsed_name(m_context.get(), name_ptr);
		
		throw std::runtime_error("krb5_unparse_name (" + std::to_string(ret) + "): " + get_error_message(m_context.get(), ret));
	}

	std::string name(name_ptr);
	krb5_free_unparsed_name(m_context.get(), name_ptr);

	return name;
}

krb5_kvno KrbKeytabEntry::get_kvno() {

	return m_entry.vno;
}

krb5_enctype KrbKeytabEntry::get_enctype() {

	return m_entry.key.enctype;
}

std::time_t KrbKeytabEntry::get_timestamp() {

	return m_entry.timestamp;
}


KrbKeytabCursor::KrbKeytabCursor(KrbContext &context, KrbKeytab &keytab, krb5_kt_cursor cursor)
	: m_context(context),
	m_keytab(keytab),
	m_cursor(cursor),
	m_entry(context) {

}

KrbKeytabCursor::KrbKeytabCursor(KrbKeytabCursor &&other)
	: m_context(other.m_context),
	m_keytab(other.m_keytab),
	m_cursor(other.m_cursor),
	m_entry(std::move(other.m_entry)) {

	other.m_cursor = nullptr;
}

KrbKeytabCursor::~KrbKeytabCursor() {

	if (m_cursor) {
		krb5_kt_end_seq_get(m_context, m_keytab, &m_cursor);
		m_cursor = nullptr;
	}
}

bool KrbKeytabCursor::has_next() {

	krb5_keytab_entry entry = {0};
	krb5_error_code ret = krb5_kt_next_entry(m_context, m_keytab, &entry, &m_cursor);
	
	if (ret && ret != KRB5_KT_END) {
		krb5_free_keytab_entry_contents(m_context, &entry);
		throw std::runtime_error("krb5_kt_next_entry (" + std::to_string(ret) + "): " + get_error_message(m_context, ret));
	}

	if (ret != KRB5_KT_END) {
		m_entry = KrbKeytabEntry(m_context, entry);
	} else {
		krb5_free_keytab_entry_contents(m_context, &entry);
		m_entry = KrbKeytabEntry(m_context);
	}

	return ret != KRB5_KT_END;
}

KrbKeytabEntry KrbKeytabCursor::get() {

	if (m_entry.is_freed()) {
		throw std::logic_error("entry already fetched from cursor");
	}
	
	return std::move(m_entry);
}


krb5_data string_to_krb_data(const std::string &data) {

	krb5_data krb_data = {0};

	krb_data.length = data.size();
	krb_data.data = const_cast<char *>(data.c_str());

	return krb_data;
}

std::string krb_data_to_string(krb5_data &krb_data) {

	return std::string(krb_data.data, krb_data.length);
}

std::string get_error_message(krb5_context context, krb5_error_code code) {

	const char *message_ptr = krb5_get_error_message(context, code);
	std::string message = std::string(message_ptr);

	krb5_free_error_message(context, message_ptr);
	return message;
}


