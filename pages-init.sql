CREATE TABLE IF NOT EXISTS `assets` (
	`id` text PRIMARY KEY NOT NULL,
	`memory_id` text,
	`object_key` text NOT NULL,
	`kind` text NOT NULL,
	`size` integer NOT NULL,
	`position` integer NOT NULL
);

CREATE INDEX IF NOT EXISTS `assets_memory_idx` ON `assets` (`memory_id`);
CREATE TABLE IF NOT EXISTS `attempts` (
	`key` text PRIMARY KEY NOT NULL,
	`count` integer NOT NULL,
	`expires` integer NOT NULL
);

CREATE TABLE IF NOT EXISTS `authors` (
	`id` text PRIMARY KEY NOT NULL,
	`token_hash` text NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS `authors_token_hash_unique` ON `authors` (`token_hash`);
CREATE TABLE IF NOT EXISTS `memories` (
	`id` text PRIMARY KEY NOT NULL,
	`author_id` text NOT NULL,
	`nickname` text NOT NULL,
	`title` text NOT NULL,
	`body` text NOT NULL,
	`category` text NOT NULL,
	`happened_at` text NOT NULL,
	`tags` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);

CREATE TABLE IF NOT EXISTS `sessions` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`author_id` text NOT NULL,
	`role` text NOT NULL,
	`expires` integer NOT NULL,
	`version` integer NOT NULL
);

CREATE TABLE IF NOT EXISTS `settings` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL
);

CREATE TABLE IF NOT EXISTS `messages` (
	`id` text PRIMARY KEY NOT NULL,
	`author_id` text NOT NULL,
	`nickname` text NOT NULL,
	`body` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);

CREATE INDEX IF NOT EXISTS `messages_created_idx` ON `messages` (`created_at`);