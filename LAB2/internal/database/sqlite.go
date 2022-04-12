package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

const driverName = "sqlite3"

type Entry struct {
	User           string
	HashedPassword string
	ResetPassword  bool
}

type Manager struct {
	db *sql.DB
}

func CreateDatabaseEntry(user, hashedPassword string, resetPassword bool) Entry {
	return Entry{
		User:           user,
		HashedPassword: hashedPassword,
		ResetPassword:  resetPassword,
	}
}

func CreateDatabaseManager(databaseFilePath string) (Manager, func(), error) {
	db, err := sql.Open(driverName, databaseFilePath)
	if err != nil {
		return Manager{}, nil, err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS passwords (User TEXT PRIMARY KEY, hashedPassword TEXT NOT NULL, resetPassword INT NOT NULL)")
	if err != nil {
		return Manager{}, nil, err
	}

	dbCloseFunc := func() {
		err := db.Close()
		if err != nil {
			log.Fatal(err)
		}
	}

	return Manager{
		db: db,
	}, dbCloseFunc, nil
}

func (dbManager Manager) SaveDatabaseEntry(dbEntry Entry) error {
	stmt, err := dbManager.db.Prepare(
		"INSERT OR REPLACE INTO passwords (User, hashedPassword, resetPassword) VALUES (?, ?, ?)",
	)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(dbEntry.User, dbEntry.HashedPassword, dbEntry.ResetPassword)
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

func (dbManager Manager) GetDatabaseEntry(user string) (Entry, error) {
	rows, err := dbManager.db.Query(
		"SELECT * FROM passwords WHERE User=?", user,
	)
	if err != nil {
		return Entry{}, err
	}

	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(rows)

	for rows.Next() {
		var user string
		var hashedPassword string
		var resetPassword bool
		err = rows.Scan(&user, &hashedPassword, &resetPassword)
		if err != nil {
			return Entry{}, err
		}

		return Entry{
			User:           user,
			HashedPassword: hashedPassword,
			ResetPassword:  resetPassword,
		}, nil
	}

	return Entry{}, nil
}

func (dbManager Manager) RemoveDatabaseEntry(dbEntry Entry) error {
	stmt, err := dbManager.db.Prepare(
		"DELETE FROM passwords WHERE user=?",
	)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(dbEntry.User)
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
