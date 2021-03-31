#ifndef H_KRB5_GUARDS
#define H_KRB5_GUARDS


#include <krb5.h>


class krb5_context_guard {

public:
	krb5_context_guard(krb5_context &context);
	~krb5_context_guard();

private:
	krb5_context &m_context;
};

class krb5_keytab_guard {

public:
	krb5_keytab_guard(krb5_context &context, krb5_keytab &keytab);
	~krb5_keytab_guard();

private:
	krb5_context &m_context;
	krb5_keytab &m_keytab;
};

class krb5_keyblock_guard {

public:
	krb5_keyblock_guard(krb5_context &context, krb5_keyblock &keyblock);
	~krb5_keyblock_guard();

private:
	krb5_context &m_context;
	krb5_keyblock &m_keyblock;
};


class krb5_principal_guard {

public:
	krb5_principal_guard(krb5_context &context, krb5_principal &principal);
	~krb5_principal_guard();

private:
	krb5_context &m_context;
	krb5_principal &m_principal;
};


#endif

