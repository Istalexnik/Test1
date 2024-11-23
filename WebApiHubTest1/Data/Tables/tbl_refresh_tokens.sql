CREATE TABLE tbl_refresh_tokens (
    col_id INT IDENTITY(1,1) PRIMARY KEY,
    col_user_id INT NOT NULL,
    col_token NVARCHAR(256) NOT NULL,
    col_expires_at DATETIME NOT NULL,
    col_created_at DATETIME NOT NULL,
    col_revoked_at DATETIME NULL,
    col_replaced_by_token NVARCHAR(256) NULL,
    FOREIGN KEY (col_user_id) REFERENCES tbl_users(col_id)
);