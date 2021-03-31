#ifndef H_KRB_OBJECTS
#define H_KRB_OBJECTS

#include <ctime>
#include <functional>
#include <string>

#include <krb5.h>


class KrbPrincipal;
class KrbKeyblock;

class KrbKeytab;

class KrbContext {

public:
	KrbContext();
	KrbContext(KrbContext &&other);
	~KrbContext();

	KrbContext(const KrbContext &other) = delete;
	KrbContext &operator= (const KrbContext &other) = delete;

	KrbKeytab resolve_keytab(const std::string &name);
	KrbPrincipal parse_name(const std::string &name);
	KrbKeyblock string_to_key(krb5_enctype enctype, const std::string &string, const std::string &salt);

	operator krb5_context &() {
		return m_context;
	}

private:
	krb5_context m_context;
};


class KrbPrincipal {

public:
	KrbPrincipal(KrbContext &context, krb5_principal principal);
	KrbPrincipal(KrbPrincipal &&other);
	~KrbPrincipal();

	KrbPrincipal(const KrbPrincipal &other) = delete;
	KrbPrincipal &operator= (const KrbPrincipal &other) = delete;

	operator krb5_principal &() {
		return m_principal;
	}

	std::string get_realm();
	std::string get_name();

private:
	KrbContext &m_context;
	krb5_principal m_principal;
};


class KrbKeyblock {

public:
	KrbKeyblock(KrbContext &context, krb5_keyblock keyblock);
	KrbKeyblock(KrbKeyblock &&other);
	~KrbKeyblock();

	KrbKeyblock(const KrbKeyblock &other) = delete;
	KrbKeyblock &operator= (const KrbKeyblock &other) = delete;

	operator krb5_keyblock &() {
		return m_keyblock;
	}

private:
	KrbContext &m_context;
	bool m_freed;
	krb5_keyblock m_keyblock;
};


class KrbKeytabEntry;
class KrbKeytabCursor;

class KrbKeytab {

public:
	KrbKeytab(KrbContext &context, krb5_keytab keytab);
	KrbKeytab(KrbKeytab &&other);
	~KrbKeytab();

	KrbKeytab(const KrbKeytab &other) = delete;
	KrbKeytab &operator= (const KrbKeytab &other) = delete;

	operator krb5_keytab &() {
		return m_keytab;
	}

	void add_entry(KrbPrincipal &principal, KrbKeyblock &keyblock, krb5_kvno vno);
	void delete_entry(KrbKeytabEntry &entry);
	KrbKeytabCursor get_cursor();

private:
	KrbContext &m_context;
	krb5_keytab m_keytab;
};

class KrbKeytabEntry {

public:
	KrbKeytabEntry(KrbContext &context);
	KrbKeytabEntry(KrbContext &context, krb5_keytab_entry entry);
	KrbKeytabEntry(KrbKeytabEntry &&other);
	~KrbKeytabEntry();

	KrbKeytabEntry &operator= (KrbKeytabEntry &&other);

	KrbKeytabEntry(const KrbKeytabEntry &other) = delete;
	KrbKeytabEntry &operator= (const KrbKeytabEntry &other) = delete;

	operator krb5_keytab_entry &() {
		return m_entry;
	}

	krb5_keytab_entry *get_ptr();

	bool is_freed();

	std::string get_principal_name();
	krb5_kvno get_kvno();
	krb5_enctype get_enctype();
	std::time_t get_timestamp();

private:
	void free_entry();

	std::reference_wrapper<KrbContext> m_context;
	bool m_freed;
	krb5_keytab_entry m_entry;

};

class KrbKeytabCursor {

public:
	KrbKeytabCursor(KrbContext &context, KrbKeytab &keytab, krb5_kt_cursor cursor);
	KrbKeytabCursor(KrbKeytabCursor &&other);
	~KrbKeytabCursor();

	KrbKeytabCursor(const KrbKeytabCursor &other) = delete;
	KrbKeytabCursor &operator= (const KrbKeytabCursor &other) = delete;

	bool has_next();
	KrbKeytabEntry get();

private:
	KrbContext &m_context;
	KrbKeytab &m_keytab;
	krb5_kt_cursor m_cursor;
	KrbKeytabEntry m_entry;
};


#endif
