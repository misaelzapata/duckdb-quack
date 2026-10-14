// Standalone native-policy contract test. Link against DuckDB and the static Quack extension.
#include "duckdb.hpp"
#include "duckdb/common/atomic.hpp"
#include "quack_extension.hpp"
#include "quack_message.hpp"
#include "quack_security.hpp"
#include "quack_server.hpp"

#include <iostream>
#include <stdexcept>

using namespace duckdb;

static idx_t assertions = 0;

static void Require(bool value, const char *message) {
	if (!value) {
		throw std::runtime_error(message);
	}
	assertions++;
}

class ContractPolicy final : public QuackSecurityPolicy {
public:
	atomic<idx_t> requests {0};
	atomic<idx_t> admissions {0};
	atomic<idx_t> authentications {0};
	atomic<idx_t> authorizations {0};
	atomic<idx_t> bound_authorizations {0};
	bool banned = false;
	bool deny_connect = false;
	bool throw_auth = false;
	bool deny_sql = false;
	bool deny_bound = false;

	bool AdmitConnection(const string &peer) override {
		admissions++;
		return !deny_connect && KnownPeer(peer);
	}
	bool AdmitRequest(const string &peer) override {
		requests++;
		return !banned && KnownPeer(peer);
	}
	bool Authenticate(const string &, const string &auth, QuackIdentity &identity) override {
		authentications++;
		if (throw_auth) {
			throw std::runtime_error(auth);
		}
		if (auth == "reader:test-password") {
			identity = {"reader", true};
			return true;
		}
		return false;
	}
	void Authorize(Connection &connection, const QuackIdentity &identity, const string &) override {
		authorizations++;
		Require(connection.context != nullptr && identity.account == "reader", "wrong authorizer session");
		if (deny_sql) {
			throw PermissionException("test SQL denial");
		}
	}
	void AuthorizeBound(const QuackIdentity &identity, const StatementProperties &) override {
		bound_authorizations++;
		Require(identity.account == "reader", "wrong bound identity");
		if (deny_bound) {
			throw PermissionException("test bound denial");
		}
	}

private:
	static bool KnownPeer(const string &peer) {
		return peer == "127.0.0.1" || peer == "127.0.0.2";
	}
};

class ContractServer final : public QuackServer {
public:
	explicit ContractServer(Connection &connection)
	    : QuackServer(*connection.context, QuackUri("quack:127.0.0.1:0"), "owner-test-token") {
	}

	unique_ptr<QuackMessage> Send(const QuackMessage &message, const string &peer = "127.0.0.1") {
		MemoryStream stream;
		message.ToMemoryStream(stream);
		return HandleMessage(stream, peer);
	}
};

static void ExpectError(unique_ptr<QuackMessage> response) {
	Require(response->Type() == MessageType::ERROR_RESPONSE, "request unexpectedly succeeded");
}

static void ExpectPrepared(unique_ptr<QuackMessage> response) {
	Require(response->Type() == MessageType::PREPARE_RESPONSE, "query unexpectedly failed");
}

static PrepareRequestMessage Query(const string &session, const string &sql) {
	return PrepareRequestMessage(session, sql, hugeint_t {0, 0});
}

int main() {
	try {
		DuckDB db;
		db.LoadStaticExtension<QuackExtension>();
		Connection owner(db);
		Require(!owner.Query("CREATE TABLE secured(value INTEGER)")->HasError(), "setup failed");
		{
			ContractServer legacy(owner);
			auto response = legacy.Send(ConnectionRequestMessage("owner-test-token", "", 300), "");
			Require(response->Type() == MessageType::CONNECTION_RESPONSE, "legacy authentication changed");
		}
		auto policy = make_shared_ptr<ContractPolicy>();
		SetQuackSecurityPolicy(*db.instance, policy);
		ContractServer server(owner);
		// Clearing installation state must not downgrade a server that already captured the policy.
		SetQuackSecurityPolicy(*db.instance, nullptr);
		ExpectError(server.Send(ConnectionRequestMessage("owner-test-token", "", 300)));
		auto auth_count = policy->authentications.load();
		ExpectError(server.Send(ConnectionRequestMessage("reader:test-password", "", 300), ""));
		ExpectError(server.Send(ConnectionRequestMessage("reader:test-password", "", 300), "unknown"));
		Require(policy->authentications == auth_count, "unknown peer reached authentication");
		policy->deny_connect = true;
		ExpectError(server.Send(ConnectionRequestMessage("reader:test-password", "", 300)));
		Require(policy->authentications == auth_count, "denied connection reached authentication");
		policy->deny_connect = false;
		policy->throw_auth = true;
		auto auth_error = server.Send(ConnectionRequestMessage("secret-must-not-appear", "", 300));
		Require(auth_error->Type() == MessageType::ERROR_RESPONSE, "auth exception escaped");
		Require(auth_error->Cast<ErrorResponse>().ErrorMessage().find("secret-must-not-appear") == string::npos,
		        "authentication exception leaked credentials");
		policy->throw_auth = false;
		auto response = server.Send(ConnectionRequestMessage("reader:test-password", "", 300));
		Require(response->Type() == MessageType::CONNECTION_RESPONSE, "reader authentication failed");
		auto session = response->ConnectionId();
		auto connection = server.GetConnection(session);
		Require(connection->identity.account == "reader" && connection->identity.read_only, "identity not stored");
		Require(connection->peer == "127.0.0.1", "peer not stored");
		ExpectError(server.Send(HeartbeatRequestMessage(session), "127.0.0.2"));

		auto bound_count = policy->bound_authorizations.load();
		ExpectPrepared(server.Send(Query(session, "SELECT 42")));
		Require(policy->bound_authorizations > bound_count, "general query missed bound authorization");
		auto prepare = Query(session, "SELECT 42");
		prepare.SetPrepareOnly(true);
		bound_count = policy->bound_authorizations;
		ExpectPrepared(server.Send(prepare));
		Require(policy->bound_authorizations > bound_count, "PrepareOnly missed bound authorization");
		auto write_prepare = Query(session, "INSERT INTO secured VALUES (1)");
		write_prepare.SetPrepareOnly(true);
		ExpectError(server.Send(write_prepare));
		ExpectError(server.Send(Query(session, "INSERT INTO secured VALUES (1)")));
		auto parameter_write = Query(session, "INSERT INTO secured VALUES ($1)");
		parameter_write.SetParameters({"1"}, {Value::INTEGER(2)});
		ExpectError(server.Send(parameter_write));
		// Seed a statement through the trusted host so the independent EXECUTE check is exercised.
		Require(!connection->duckdb_connection->Query("PREPARE trusted_write AS INSERT INTO secured VALUES (3)")
		             ->HasError(),
		        "prepared-write setup failed");
		ExpectError(server.Send(Query(session, "EXECUTE trusted_write")));
		Require(owner.Query("SELECT count(*) FROM secured")->GetValue<int64_t>(0, 0) == 0, "read-only write executed");

		bound_count = policy->bound_authorizations;
		ExpectPrepared(server.Send(Query(session, "BEGIN")));
		ExpectPrepared(server.Send(Query(session, "ROLLBACK")));
		Require(policy->bound_authorizations >= bound_count + 2, "transaction controls missed bound authorization");
		auto probe = Query(session, "");
		probe.SetTransactionStateOnly(true);
		auto authorized_count = policy->authorizations.load();
		ExpectPrepared(server.Send(probe));
		Require(policy->authorizations > authorized_count, "transaction probe missed authorization");
		policy->deny_sql = true;
		ExpectError(server.Send(Query(session, "SELECT 42")));
		policy->deny_sql = false;
		policy->deny_bound = true;
		ExpectError(server.Send(Query(session, "SELECT 42")));
		policy->deny_bound = false;
		policy->banned = true;
		ExpectError(server.Send(HeartbeatRequestMessage(session)));
		ExpectError(server.Send(Query(session, "SELECT 42")));
		policy->banned = false;
		Require(server.Send(HeartbeatRequestMessage(session))->Type() == MessageType::SUCCESS_RESPONSE,
		        "admitted heartbeat failed");
		std::cout << assertions << " native Quack security assertions passed\n";
		return 0;
	} catch (const std::exception &ex) {
		std::cerr << ex.what() << '\n';
		return 1;
	}
}
