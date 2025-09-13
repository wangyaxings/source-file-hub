package di

import (
    "database/sql"
)

// Container provides a simple DI skeleton to be expanded in later phases.
type Container struct {
    DB *sql.DB
}

func New(db *sql.DB) *Container {
    return &Container{DB: db}
}

