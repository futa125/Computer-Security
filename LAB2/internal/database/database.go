package database

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const (
	driverName = "sqlite3"

	createTableQuery = "CREATE TABLE IF NOT EXISTS passwords (username TEXT PRIMARY KEY, hashedPassword TEXT NOT NULL, resetPassword INT NOT NULL)"
	insertQuery      = "INSERT OR REPLACE INTO passwords (username, hashedPassword, resetPassword) VALUES (?, ?, ?)"
	selectQuery      = "SELECT * FROM passwords WHERE username=?"
	removeQuery      = "DELETE FROM passwords WHERE username=?"
)

type Entry struct {
	Username       string
	HashedPassword string
	ResetPassword  bool
}

type Client struct {
	db *sql.DB
}

func CreateDatabaseClient(dbFilePath string) (client Client, err error) {
	db, err := sql.Open(driverName, dbFilePath)
	client = Client{}
	if err != nil {
		return client, err
	}

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return client, err
	}

	client = Client{
		db: db,
	}

	return client, err
}

func (client Client) SaveDatabaseEntry(dbEntry Entry) (err error) {
	stmt, err := client.db.Prepare(insertQuery)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(dbEntry.Username, dbEntry.HashedPassword, dbEntry.ResetPassword)
	if err != nil {
		return err
	}

	defer func(stmt *sql.Stmt) {
		closeErr := stmt.Close()
		if closeErr != nil {
			err = closeErr
		}
	}(stmt)

	return err
}

func (client Client) GetDatabaseEntry(user string) (entry Entry, err error) {
	rows, err := client.db.Query(selectQuery, user)
	entry = Entry{}
	if err != nil {
		return entry, err
	}

	defer func(rows *sql.Rows) {
		closeErr := rows.Close()
		if closeErr != nil {
			err = closeErr
		}
	}(rows)

	if rows.Next() {
		var user string
		var hashedPassword string
		var resetPassword bool

		err = rows.Scan(&user, &hashedPassword, &resetPassword)
		if err != nil {
			return entry, err
		}

		entry = Entry{
			Username:       user,
			HashedPassword: hashedPassword,
			ResetPassword:  resetPassword,
		}

		return entry, nil
	}

	return entry, nil
}

func (client Client) RemoveDatabaseEntry(dbEntry Entry) (err error) {
	stmt, err := client.db.Prepare(removeQuery)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(dbEntry.Username)
	if err != nil {
		return err
	}

	defer func(stmt *sql.Stmt) {
		closeErr := stmt.Close()
		if closeErr != nil {
			err = closeErr
		}
	}(stmt)

	return err
}
