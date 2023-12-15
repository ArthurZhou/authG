package db

import (
	"database/sql"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

type Account struct {
	ID        int
	Username  string
	Hash      string
	UUID      string
	Exception string
}

func Init() {
	db, _ = sql.Open("sqlite3", "db/accounts.sqlite")
}

func Close() {
	_ = db.Close()
}

func Query(username string) (bool, Account) {
	stm, err := db.Prepare("SELECT * FROM Account WHERE Username = ?")
	if err != nil {
		return false, Account{
			Exception: err.Error(),
		}
	}
	defer func(stm *sql.Stmt) {
		_ = stm.Close()
	}(stm)

	var id int
	var hash string
	var uuid string

	err = stm.QueryRow(username).Scan(&id, &username, &hash, &uuid)
	if err != nil {
		return false, Account{
			Exception: err.Error(),
		}
	}

	data := Account{
		ID:       id,
		Username: username,
		Hash:     hash,
		UUID:     uuid,
	}
	return true, data
}

func Add(username string, hash string, uuid string) (bool, string) {
	res, err := db.Exec("INSERT INTO Account(Username, Hash, uuid) VALUES (?, ?, ?)", username, hash, uuid)
	if err != nil {
		return false, err.Error()
	}

	n, err := res.RowsAffected()
	if err != nil {
		return false, err.Error()
	}

	return true, "The add statement has affected " + strconv.FormatInt(n, 10) + " rows\n"
}

func Del(username string) (bool, string) {
	res, err := db.Exec("DELETE FROM Account WHERE Username = ?", username)
	if err != nil {
		return false, err.Error()
	}

	n, err := res.RowsAffected()
	if err != nil {
		return false, err.Error()
	}

	return true, "The del statement has affected " + strconv.FormatInt(n, 10) + " rows\n"
}
