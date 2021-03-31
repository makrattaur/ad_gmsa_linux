#include "krb5_guards.hpp"

krb5_context_guard::krb5_context_guard(krb5_context &context) : m_context(context) {
}

krb5_context_guard::~krb5_context_guard() {
	krb5_free_context(m_context);
}


krb5_keytab_guard::krb5_keytab_guard(krb5_context &context, krb5_keytab &keytab) : m_context(context), m_keytab(keytab) {
}

krb5_keytab_guard::~krb5_keytab_guard() {
	krb5_kt_close(m_context, m_keytab);
}


krb5_keyblock_guard::krb5_keyblock_guard(krb5_context &context, krb5_keyblock &keyblock) : m_context(context), m_keyblock(keyblock) {
}

krb5_keyblock_guard::~krb5_keyblock_guard() {
	krb5_free_keyblock_contents(m_context, &m_keyblock);
}


krb5_principal_guard::krb5_principal_guard(krb5_context &context, krb5_principal &principal) : m_context(context), m_principal(principal) {
}

krb5_principal_guard::~krb5_principal_guard() {
	krb5_free_principal (m_context, m_principal);
}

