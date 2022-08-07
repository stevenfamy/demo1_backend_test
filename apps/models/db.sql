CREATE TABLE `aha_test`.`users` (
  `id` VARCHAR(36) NOT NULL,
  `email` VARCHAR(100) NULL,
  `password` VARCHAR(255) NULL,
  `verification` TINYINT NULL,
  `last_login` INT NULL,
  `status` TINYINT NULL,
  `created_on` INT NULL,
  `total_login` INT NULL,
  PRIMARY KEY (`id`));

CREATE TABLE `aha_test`.`users_oauth` (
  `id` VARCHAR(36) NOT NULL,
  `user_id` VARCHAR(36) NULL,
  `type` VARCHAR(10) NULL,
  `oauth_user_id` VARCHAR(36) NULL,
  `connected_at` INT NULL,
  PRIMARY KEY (`id`));

CREATE TABLE `aha_test`.`users_profile` (
  `id` VARCHAR(36) NOT NULL,
  `user_id` VARCHAR(36) NULL,
  `first_name` VARCHAR(50) NULL,
  `last_name` VARCHAR(50) NULL,
  PRIMARY KEY (`id`));

CREATE TABLE `aha_test`.`users_session` (
  `id` VARCHAR(36) NOT NULL,
  `user_id` VARCHAR(36) NULL,
  `selector` VARCHAR(255) NULL,
  `hashed_token` VARCHAR(255) NULL,
  `created_on` INT NULL,
  `session_method` VARCHAR(10) NULL,
  `last_seen` INT NULL,
  PRIMARY KEY (`id`));

CREATE TABLE `aha_test`.`users_tokens` (
    `id` VARCHAR(36) NOT NULL,
    `user_id` VARCHAR(36) NULL,
    `tokens` VARCHAR(255) NULL,
    `created_on` INT NULL,
    `expired_on` INT NULL,
    `token_type` VARCHAR(20) NULL,
    PRIMARY KEY (`id`));
