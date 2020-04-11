package util

import (
	"fmt"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
)

var db *gorm.DB

func ConnectDb() (*gorm.DB, error) {
	var err error
	if db == nil {
		username := viper.GetString("db.username")
		password := viper.GetString("db.password")
		database := viper.GetString("db.database")

		host := viper.GetString("db.host")
		port := viper.GetInt("db.port")

		var sslMode string
		if viper.GetBool("db.ssl") {
			sslMode = "enable"
		} else {
			sslMode = "disable"
		}

		db, err = gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s", host, port, username, database, password, sslMode))
	}

	return db, err
}

func SetDb(newDb *gorm.DB) {
	db = newDb
}

func GetDb() *gorm.DB {
	if db == nil {
		if _, err := ConnectDb(); err != nil {
			panic(err)
		}
	}

	return db
}
