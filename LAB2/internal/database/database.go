package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

const (
	driverName = "sqlite3"

	createTableQuery = "CREATE TABLE IF NOT EXISTS passwords (hashedUser TEXT PRIMARY KEY, hashedPassword TEXT NOT NULL, resetPassword INT NOT NULL)"
	insertQuery      = "INSERT OR REPLACE INTO passwords (hashedUser, hashedPassword, resetPassword) VALUES (?, ?, ?)"
	selectQuery      = "SELECT * FROM passwords WHERE hashedUser=?"
	removeQuery      = "DELETE FROM passwords WHERE hashedUser=?"
)

type Entry struct {
	HashedUser     string
	HashedPassword string
	ResetPassword  bool
}

type Client struct {
	db *sql.DB
}

func CreateDatabaseClient(dbFilePath string) (Client, func(), error) {
	db, err := sql.Open(driverName, dbFilePath)
	if err != nil {
		return Client{}, nil, err
	}

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return Client{}, nil, err
	}

	dbCloseFunc := func() {
		err := db.Close()
		if err != nil {
			log.Fatal(err)
		}
	}

	return Client{
		db: db,
	}, dbCloseFunc, nil
}

func (client Client) SaveDatabaseEntry(dbEntry Entry) error {
	stmt, err := client.db.Prepare(insertQuery)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(dbEntry.HashedUser, dbEntry.HashedPassword, dbEntry.ResetPassword)
	if err != nil {
		return err
	}

	defer func(stmt *sql.Stmt) {
		err := stmt.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(stmt)

	return nil
}

func (client Client) GetDatabaseEntry(hashedUser string) (Entry, error) {
	rows, err := client.db.Query(selectQuery, hashedUser)
	if err != nil {
		return Entry{}, err
	}

	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(rows)

	if rows.Next() {
		var hashedUser string
		var hashedPassword string
		var resetPassword bool
		err = rows.Scan(&hashedUser, &hashedPassword, &resetPassword)
		if err != nil {
			return Entry{}, err
		}

		return Entry{
			HashedUser:     hashedUser,
			HashedPassword: hashedPassword,
			ResetPassword:  resetPassword,
		}, nil
	}

	return Entry{}, nil
}

func (client Client) RemoveDatabaseEntry(dbEntry Entry) error {
	stmt, err := client.db.Prepare(removeQuery)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(dbEntry.HashedUser)
	if err != nil {
		return err
	}

	defer func(stmt *sql.Stmt) {
		err := stmt.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(stmt)

	return nil
}
