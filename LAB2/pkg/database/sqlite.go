package database

import (
	"database/sql"
	"log"
)

const driverName = "sqlite3"

type DatabaseEntry struct {
	user           string
	hashedPassword string
}

type DatabaseManager struct {
	db *sql.DB
}

func CreateDatabaseManager(databaseFilePath string) (DatabaseManager, func(), error) {
	db, err := sql.Open(driverName, databaseFilePath)
	if err != nil {
		return DatabaseManager{}, nil, err
	}

	returnFunc := func() {
		err := db.Close()
		if err != nil {
			log.Fatal(err)
		}
	}

	return DatabaseManager{
		db: db,
	}, returnFunc, nil
}

func (dbManager DatabaseManager) saveDatabaseEntry(dbEntry DatabaseEntry) error {
	stmt, err := dbManager.db.Prepare(
		"INSERT INTO passwords (user, hashedPassword) VALUES (?, ?)",
	)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(nil, dbEntry.user, dbEntry.hashedPassword)
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

func (dbManager DatabaseManager) getDatabaseEntry(user string) (DatabaseEntry, error) {
	rows, err := dbManager.db.Query(
		"SELECT * FROM passwords WHERE user=?", user,
	)
	if err != nil {
		return DatabaseEntry{}, err
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
		err = rows.Scan(&user, &hashedPassword)
		if err != nil {
			return DatabaseEntry{}, err
		}

		return DatabaseEntry{
			user:           user,
			hashedPassword: hashedPassword,
		}, nil
	}

	return DatabaseEntry{}, nil
}
