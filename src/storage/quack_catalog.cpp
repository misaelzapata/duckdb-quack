#include "duckdb/common/exception.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/prepared_statement.hpp"
#include "duckdb/main/prepared_statement_data.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/drop_info.hpp"
#include "duckdb/parser/sql_statement.hpp"
#include "duckdb/planner/operator/logical_insert.hpp"
#include "duckdb/storage/database_size.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"

#include "storage/quack_catalog.hpp"
#include "storage/quack_table.hpp"
#include "quack_scan.hpp"
#include "storage/quack_insert.hpp"
#include "quack_message.hpp"
#include "quack_client.hpp"
#include "storage/quack_transaction.hpp"

// FIXME bunch of stuff copied from postgres scanner, can probably be simplified!

namespace duckdb {

//! Catalogs are shared by duplicate DuckDB connections; SQL sessions must not be shared.
class QuackConnectState : public ClientContextState {
public:
	static constexpr const char *KEY = "quack_connect_sessions";
	mutex lock;
	unordered_map<idx_t, shared_ptr<QuackClientConnection>> sessions;
	unique_ptr<QuackPreparedMetadata> result_metadata;
	vector<Identifier> result_names;

	bool CanRequestRebind() override {
		return true;
	}
	void QueryBegin(ClientContext &context) override {
		result_metadata.reset();
		result_names.clear();
	}
	RebindQueryInfo OnFinalizePrepare(ClientContext &context, PreparedStatementData &statement,
	                                  PreparedStatementMode mode) override {
		if (result_metadata && context.IsConnected()) {
			if (result_names.size() != statement.names.size()) {
				throw InternalException("Quack result names do not match the local transport schema");
			}
			// The local SELECT is only a transport plan. Native clients must see the original SQL's result metadata.
			statement.names = std::move(result_names);
			statement.statement_type = result_metadata->statement_type;
			statement.properties.return_type = result_metadata->return_type;
			statement.properties.output_type = result_metadata->output_type;
			result_metadata.reset();
		}
		return RebindQueryInfo::DO_NOT_REBIND;
	}

	void ConnectionClosed() override {
		unordered_map<idx_t, shared_ptr<QuackClientConnection>> closing;
		{
			lock_guard<mutex> guard(lock);
			closing.swap(sessions);
		}
		for (auto &entry : closing) {
			entry.second->Disconnect();
		}
	}
};

QuackCatalog::QuackCatalog(AttachedDatabase &db_p, const QuackUri &server_uri, ClientContext &context,
                           const string &token, string client_id, idx_t heartbeat_timeout_seconds)
    : Catalog(db_p) {
	auth_token = token;
	client_identifier = client_id;
	requested_heartbeat_timeout = heartbeat_timeout_seconds;
	// connect to the server
	client_connection =
	    QuackClient::ConnectToServer(context, server_uri, token, std::move(client_id), heartbeat_timeout_seconds);

	// load the entire catalog up-front
	auto load_info = LoadCatalog(context);
	schemas = make_uniq<QuackSchemaSet>(context, *this, load_info);
}

QuackLoadCatalogData QuackCatalog::LoadCatalog(ClientContext &context) {
	QuackLoadCatalogData result;
	result.schemas = ExecuteCommandInternal(context, QuackSchemaSet::GetLoadQuery());
	result.tables = ExecuteCommandInternal(context, QuackTableSet::GetLoadQuery());
	return result;
}

QuackCatalog::~QuackCatalog() {
}

void QuackCatalog::Initialize(bool load_builtin) {
}

//! The (possibly nested) schema path a lookup refers to. A qualified lookup always leads with the catalog
//! component (e.g. [catalog, schema] or a nested [catalog, s1, s2]); a bare lookup is just [schema]. The
//! leading catalog component and any empty placeholders are dropped.
static vector<Identifier> GetSchemaPath(const EntryLookupInfo &schema_lookup) {
	auto &qualified_path = schema_lookup.GetQualifiedName().Path();
	vector<Identifier> schema_path;
	for (idx_t i = 0; i < qualified_path.size(); i++) {
		if (i == 0 && qualified_path.size() > 1) {
			continue;
		}
		if (qualified_path[i].empty()) {
			continue;
		}
		schema_path.push_back(qualified_path[i]);
	}
	return schema_path;
}

optional_ptr<SchemaCatalogEntry> QuackCatalog::LookupSchema(CatalogTransaction transaction,
                                                            const EntryLookupInfo &schema_lookup,
                                                            OnEntryNotFound if_not_found) {
	auto schema_path = GetSchemaPath(schema_lookup);
	// navigate the schema chain: the outermost schema lives in the catalog, each nested one in its parent
	reference<QuackCatalogSet> current_set = *schemas;
	optional_ptr<CatalogEntry> entry;
	for (idx_t i = 0; i < schema_path.size(); i++) {
		entry = current_set.get().GetEntry(schema_path[i].GetIdentifierName());
		if (!entry) {
			switch (if_not_found) {
			case OnEntryNotFound::THROW_EXCEPTION:
				throw BinderException("Schema with name \"%s\" not found", schema_path[i].GetIdentifierName());
			case OnEntryNotFound::RETURN_NULL:
			default:
				return nullptr;
			}
		}
		current_set = entry->Cast<QuackSchemaCatalogEntry>().Schemas();
	}
	if (!entry) {
		return nullptr;
	}
	return entry->Cast<SchemaCatalogEntry>();
}

const QuackUri &QuackCatalog::GetServerUri() {
	return client_connection->ServerURI();
}

unique_ptr<ColumnDataCollection> QuackCatalog::ExecuteCommandInternal(ClientContext &context, const string &query) {
	// FIXME this will break with many results!
	auto chunk_collection = make_uniq<ColumnDataCollection>(Allocator::DefaultAllocator());
	// get a client to query
	auto client_wrapper = client_connection->GetClient(context);
	auto &client = client_wrapper->GetClient();
	auto response =
	    client.Request<PrepareResponseMessage>(context, make_uniq<PrepareRequestMessage>(GetConnectionId(), query, 0));
	chunk_collection->Initialize(response->Types());
	for (auto &chunk : response->MutableResults()) {
		chunk_collection->Append(chunk->Chunk());
	}
	return chunk_collection;
}

shared_ptr<QuackClientConnection> QuackCatalog::GetClientConnection() {
	return client_connection;
}

shared_ptr<QuackClientConnection> QuackCatalog::GetConnectClientConnection(ClientContext &context) {
	auto state = context.registered_state->GetOrCreate<QuackConnectState>(QuackConnectState::KEY);
	lock_guard<mutex> guard(state->lock);
	auto &session = state->sessions[GetOid()];
	if (!session) {
		session = QuackClient::ConnectToServer(context, GetServerUri(), auth_token, client_identifier,
		                                       requested_heartbeat_timeout);
	}
	return session;
}

void QuackCatalog::Refresh(ClientContext &context) {
	auto load_info = LoadCatalog(context);
	schemas->Reload(context, *this, load_info);
}

const string &QuackCatalog::GetConnectionId() {
	return client_connection->ConnectionId();
}

QuackCatalog &QuackCatalog::GetQuackCatalog(ClientContext &context, Value &catalog_name) {
	if (catalog_name.IsNull()) {
		throw BinderException("Catalog cannot be NULL");
	}
	// look up the database to query
	auto db_name = catalog_name.GetValue<string>();
	auto &db_manager = DatabaseManager::Get(context);
	auto db = db_manager.GetDatabase(context, Identifier(db_name));
	if (!db) {
		throw BinderException("Failed to find attached database \"%s\"", db_name);
	}
	auto &catalog = db->GetCatalog();
	if (catalog.GetCatalogType() != "quack") {
		throw BinderException("Attached database \"%s\" does not refer to a Quack database", db_name);
	}
	return catalog.Cast<QuackCatalog>();
}

optional_ptr<CatalogEntry> QuackCatalog::CreateSchema(CatalogTransaction transaction, CreateSchemaInfo &info) {
	// find the set the schema goes in - the catalog itself for a top-level schema, the deepest parent for a
	// nested one. This runs before the schema is created on the server so a bad path does not leave the
	// server and the local catalog out of sync
	reference<QuackCatalogSet> target_set = *schemas;
	optional_ptr<QuackSchemaCatalogEntry> parent;
	for (auto &parent_name : info.ParentSchemas()) {
		auto parent_entry = target_set.get().GetEntry(parent_name.GetIdentifierName());
		if (!parent_entry) {
			throw CatalogException("Cannot create nested schema \"%s\": parent schema \"%s\" does not exist",
			                       info.SchemaName().GetIdentifierName(), parent_name.GetIdentifierName());
		}
		parent = &parent_entry->Cast<QuackSchemaCatalogEntry>();
		target_set = parent->Schemas();
	}

	// create the schema remotely - the local schema path is exactly how the server sees it, so the statement
	// only needs the local catalog name (the ATTACH alias) removed
	auto remote_info = unique_ptr_cast<CreateInfo, CreateSchemaInfo>(info.Copy());
	remote_info->StripCatalogQualification();
	auto &quack_transaction = QuackTransaction::Get(transaction);
	quack_transaction.Query(remote_info->ToString());

	auto schema_entry = make_uniq<QuackSchemaCatalogEntry>(*this, info, parent.get());
	return target_set.get().CreateEntry(std::move(schema_entry), info.on_conflict);
}

//! Report a schema and every schema nested inside it
static void ScanNestedSchemas(QuackSchemaCatalogEntry &schema,
                              const std::function<void(SchemaCatalogEntry &)> &callback) {
	callback(schema);
	for (auto &nested : schema.Schemas().GetAllCatalogEntries()) {
		ScanNestedSchemas(nested.get().Cast<QuackSchemaCatalogEntry>(), callback);
	}
}

void QuackCatalog::ScanSchemas(ClientContext &context, std::function<void(SchemaCatalogEntry &)> callback) {
	for (auto &schema : schemas->GetAllCatalogEntries()) {
		ScanNestedSchemas(schema.get().Cast<QuackSchemaCatalogEntry>(), callback);
	}
}

PhysicalOperator &QuackCatalog::PlanDelete(ClientContext &context, PhysicalPlanGenerator &planner, LogicalDelete &op,
                                           PhysicalOperator &plan) {
	throw NotImplementedException("PlanDelete not implemented yet");
}
PhysicalOperator &QuackCatalog::PlanUpdate(ClientContext &context, PhysicalPlanGenerator &planner, LogicalUpdate &op,
                                           PhysicalOperator &plan) {
	throw NotImplementedException("PlanUpdate not implemented yet");
}

unique_ptr<LogicalOperator> QuackCatalog::BindCreateIndex(Binder &binder, CreateStatement &stmt,
                                                          TableCatalogEntry &table, unique_ptr<LogicalOperator> plan) {
	throw NotImplementedException("BindCreateIndex not implemented yet");
}

DatabaseSize QuackCatalog::GetDatabaseSize(ClientContext &context) {
	throw NotImplementedException("GetDatabaseSize not implemented yet");
}

unique_ptr<TableRef> QuackCatalog::RemoteExecute(ClientContext &context, unique_ptr<QueryNode> node) {
	// attached-catalog path: a read of this catalog, so it joins the local transaction
	return CreateRemoteQueryRef(node->ToString(), false, true);
}

unique_ptr<TableRef> QuackCatalog::RemoteExecute(ClientContext &context, unique_ptr<SQLStatement> statement) {
	// a statement pushed down as a whole is DDL - it changes the catalog on the server, so the local
	// snapshot of the remote catalog has to be reloaded once the statement has run
	return CreateRemoteQueryRef(statement->ToString(), true);
}

unique_ptr<TableRef> QuackCatalog::RemoteExecute(ClientContext &context, const string &sql) {
	// Forward transaction control verbatim, using this ClientContext's independent server session.
	GetConnectClientConnection(context);
	return CreateRemoteQueryRef(sql, false, false, nullptr, true);
}

unique_ptr<TableRef> QuackCatalog::RemoteExecute(ClientContext &context, const string &sql,
                                               const identifier_map_t<BoundParameterData> &parameters) {
	GetConnectClientConnection(context);
	return CreateRemoteQueryRef(sql, false, false, &parameters, true);
}

void QuackCatalog::SetConnectQueryMetadata(ClientContext &context, const PrepareResponseMessage &response) {
	auto metadata = response.PreparedMetadata();
	if (!metadata) {
		throw InvalidInputException("The Quack server did not return native execution metadata; use the matching build");
	}
	auto state = context.registered_state->GetOrCreate<QuackConnectState>(QuackConnectState::KEY);
	state->result_metadata = make_uniq<QuackPreparedMetadata>(*metadata);
	state->result_names.clear();
	for (auto &name : response.Names()) {
		state->result_names.push_back(Identifier(name));
	}
}

PreparedStatementInfo QuackCatalog::RemotePrepare(ClientContext &context, SQLStatement &statement) {
	auto session = GetConnectClientConnection(context);
	auto client = session->GetClient(context);
	auto request = make_uniq<PrepareRequestMessage>(session->ConnectionId(), statement.query, hugeint_t {0, 0});
	request->SetPrepareOnly(true);
	auto response = client->GetClient().Request<PrepareResponseMessage>(context, std::move(request));
	auto metadata = response->PreparedMetadata();
	if (!metadata || metadata->parameter_names.size() != metadata->parameter_types.size()) {
		throw IOException("Quack server did not return valid prepared-statement metadata");
	}
	PreparedStatementInfo info;
	info.statement_type = metadata->statement_type;
	info.types = response->Types();
	for (auto &name : response->Names()) {
		info.names.push_back(Identifier(name));
	}
	info.named_param_map = statement.named_param_map;
	for (idx_t i = 0; i < metadata->parameter_names.size(); i++) {
		info.parameter_types.emplace(Identifier(metadata->parameter_names[i]), metadata->parameter_types[i]);
	}
	info.properties.requires_valid_transaction = metadata->requires_valid_transaction;
	info.properties.output_type = metadata->output_type;
	info.properties.bound_all_parameters = metadata->bound_all_parameters;
	info.properties.return_type = metadata->return_type;
	info.properties.parameter_count = metadata->parameter_count;
	info.properties.always_require_rebind = metadata->always_require_rebind;
	if (!metadata->read_only) {
		// Remote catalog identity is deliberately represented by the client-side attachment.
		info.properties.modified_databases[GetName()] = {{GetOid(), {}}, DatabaseModificationType()};
	}
	return info;
}

bool QuackCatalog::RemoteIsAutoCommit(ClientContext &context) {
	auto session = GetConnectClientConnection(context);
	auto client = session->GetClient(context);
	auto request = make_uniq<PrepareRequestMessage>(session->ConnectionId(), "COMMIT", hugeint_t {0, 0});
	request->SetTransactionStateOnly(true);
	auto response = client->GetClient().Request<PrepareResponseMessage>(context, std::move(request));
	return response->RemoteAutoCommit();
}

unique_ptr<TableRef> QuackCatalog::CreateRemoteQueryRef(const string &sql, bool refresh_catalog,
                                                      bool use_transaction_p,
                                                      const identifier_map_t<BoundParameterData> *parameters,
                                                      bool connect_session) {
	vector<unique_ptr<ParsedExpression>> args;
	args.push_back(ConstantExpression::FromValue(Value(GetName())));
	args.push_back(ConstantExpression::FromValue(Value(sql)));
	auto use_transaction = ConstantExpression::FromValue(Value::BOOLEAN(use_transaction_p));
	use_transaction->SetAlias("use_transaction");
	args.push_back(std::move(use_transaction));
	if (connect_session) {
		auto session = ConstantExpression::FromValue(Value::BOOLEAN(true));
		session->SetAlias("connect_session");
		args.push_back(std::move(session));
	}
	if (parameters && !parameters->empty()) {
		child_list_t<Value> fields;
		for (auto &entry : *parameters) {
			fields.emplace_back(entry.first.GetIdentifierName(), entry.second.GetValue());
		}
		auto values = ConstantExpression::FromValue(Value::STRUCT(std::move(fields)));
		values->SetAlias("parameters");
		args.push_back(std::move(values));
	}
	if (refresh_catalog) {
		auto refresh = ConstantExpression::FromValue(Value::BOOLEAN(true));
		refresh->SetAlias("refresh_catalog");
		args.push_back(std::move(refresh));
	}
	auto func_ref = make_uniq<TableFunctionRef>();
	func_ref->function = make_uniq<FunctionExpression>("quack_query_by_name", std::move(args));
	return std::move(func_ref);
}

bool QuackCatalog::InMemory() {
	return false;
}
string QuackCatalog::GetDBPath() {
	return client_connection->ServerURI().Uri();
}

void QuackCatalog::DropSchema(ClientContext &context, DropInfo &info) {
	// the resolved path is [catalog, parent schemas..., schema]; drop it remotely under the name the server
	// knows it by - the local schema path is exactly the remote qualification, only the ATTACH alias is local
	auto remote_name = info.GetQualifiedName();
	remote_name.StripCatalog();
	auto &schema_path = remote_name.Path();
	if (schema_path.empty()) {
		throw InternalException("DropSchema called without a schema name");
	}
	auto drop_info = info.Copy();
	drop_info->SetQualifiedName(remote_name);
	auto &transaction = QuackTransaction::Get(context, *this);
	transaction.Query(drop_info->ToString());

	// remove the schema from the local set it lives in
	reference<QuackCatalogSet> target_set = *schemas;
	for (idx_t i = 0; i + 1 < schema_path.size(); i++) {
		auto parent_entry = target_set.get().GetEntry(schema_path[i].GetIdentifierName());
		if (!parent_entry) {
			return;
		}
		target_set = parent_entry->Cast<QuackSchemaCatalogEntry>().Schemas();
	}
	target_set.get().DropEntry(schema_path.back().GetIdentifierName());
}

bool QuackCatalog::SupportsPushdown(const TableRef &ref) {
	if (ref.type != TableReferenceType::TABLE_FUNCTION) {
		return true;
	}
	auto &table_func_ref = ref.Cast<TableFunctionRef>();
	if (table_func_ref.function->GetExpressionClass() != ExpressionClass::FUNCTION) {
		return true;
	}
	auto &func_expr = table_func_ref.function->Cast<FunctionExpression>();
	if (func_expr.FunctionName() == "query") {
		return false;
	}
	return true;
}

} // namespace duckdb
