#pragma once

#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/winapi.hpp"

namespace duckdb {

class Connection;
class DatabaseInstance;
struct StatementProperties;

//! The identity established by the native policy, immutable for a Quack session.
struct QuackIdentity {
	string account;
	bool read_only = false;
};

//! Native security callbacks. Implementations must be safe for concurrent sessions and requests.
//! Admission and authentication return false to reject a request. Authorization throws on denial.
class QuackSecurityPolicy {
public:
	virtual ~QuackSecurityPolicy() = default;
	virtual bool AdmitConnection(const string &peer) = 0;
	virtual bool AdmitRequest(const string &peer) = 0;
	virtual bool Authenticate(const string &peer, const string &auth_string, QuackIdentity &identity) = 0;
	virtual void Authorize(Connection &connection, const QuackIdentity &identity, const string &sql) = 0;
	virtual void AuthorizeBound(const QuackIdentity &identity, const StatementProperties &properties) = 0;
};

//! Install after loading Quack and before starting its servers. Each server retains its policy snapshot.
DUCKDB_API void SetQuackSecurityPolicy(DatabaseInstance &db, shared_ptr<QuackSecurityPolicy> policy);

} // namespace duckdb
