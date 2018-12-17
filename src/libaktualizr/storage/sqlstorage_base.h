enum class DbVersion : int32_t { kEmpty = -1, kInvalid = -2 };

class SQLStorageBase {
 public:
  explicit SQLStorageBase(const StorageConfig& config, bool readonly);
  ~SQLStorageBase() override = default;
  std::string getTableSchemaFromDb(const std::string& tablename);
  bool dbMigrate();
  DbVersion getVersion();  // non-negative integer on success or -1 on error
  boost::filesystem::path dbPath() const;

 protected:
  SQLite3Guard dbConnection() const;
  bool readonly_{false};
};
