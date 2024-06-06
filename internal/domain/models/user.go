package models

type User struct {
	ID       int64
	Email    string
	Name     string
	PassHash []byte
}
