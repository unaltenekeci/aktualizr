-- Don't modify this! Create a new migration instead--see docs/schema-migrations.adoc
BEGIN TRANSACTION;

CREATE TABLE target_images_migrate(filename TEXT UNIQUE, image_data BLOB NOT NULL, bytes_read INTEGER, timestamp INTEGER);
INSERT INTO target_images_migrate SELECT (filename, image_data, NULL, NULL) FROM target_images;
DROP TABLE target_images;
ALTER TABLE target_images_migrate RENAME TO target_images;

DELETE FROM version;
INSERT INTO version VALUES(10);

COMMIT TRANSACTION;
