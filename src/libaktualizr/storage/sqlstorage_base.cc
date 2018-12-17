SQLStorageBase::SQLStorageBase(const StorageConfig& config, bool readonly) {
  boost::filesystem::path db_parent_path = dbPath().parent_path();
  if (!boost::filesystem::is_directory(db_parent_path)) {
    Utils::createDirectories(db_parent_path, S_IRWXU);
  } else {
    struct stat st {};
    stat(db_parent_path.c_str(), &st);
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
      throw StorageException("Storage directory has unsafe permissions");
    }
    if ((st.st_mode & (S_IRGRP | S_IROTH)) != 0) {
      // Remove read permissions for group and others
      chmod(db_parent_path.c_str(), S_IRWXU);
    }
  }

  if (!dbMigrate()) {
    LOG_ERROR << "SQLite database migration failed";
    // Continue to run anyway, it can't be worse
  }

}
