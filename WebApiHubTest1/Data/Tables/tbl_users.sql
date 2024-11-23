CREATE TABLE tbl_users (
    col_id INT IDENTITY(1,1) PRIMARY KEY,
    col_email NVARCHAR(50) NOT NULL UNIQUE,
    col_password_hash NVARCHAR(255) NOT NULL,
	col_is_email_confirmed BIT NOT NULL DEFAULT 0,
    col_email_confirmation_code NVARCHAR(6),
    col_email_confirmation_code_expires_at DATETIME,
	col_password_reset_code NVARCHAR(6),
    col_password_reset_code_expires_at DATETIME,
	col_new_email NVARCHAR(255),
    col_email_change_code NVARCHAR(6),
    col_email_change_code_expires_at DATETIME
);