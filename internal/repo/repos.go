package repo

import (
	"reflect"
	"strings"

	"github.com/jmoiron/sqlx"
)

type Repos struct {
	User  *UserRepo
	Role  *RoleRepo
	Token *TokenRepo
}

type Columns struct {
	allColumns   []string
	AllRaw       string
	AllPrefixed  string
	safeColumns  []string
	SafeRaw      string
	SafePrefixed string
}

func NewRepos(db *sqlx.DB) *Repos {
	return &Repos{
		User:  NewUserRepo(db),
		Role:  NewRoleRepo(db),
		Token: NewTokenRepo(db),
	}
}

func ExtractColumns[T any](model T) Columns {
	var allCols, safeCols []string
	t := reflect.TypeOf(model)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		dbTag, ok := field.Tag.Lookup("db")
		if !ok || dbTag == "-" {
			dbTag = strings.ToLower(field.Name)
		}
		allCols = append(allCols, dbTag)

		if safeTag, ok := field.Tag.Lookup("safe"); ok && safeTag == "true" {
			safeCols = append(safeCols, dbTag)
		}
	}

	allInsert := strings.Join(allCols, ", ")
	allSelect := ":" + strings.Join(allCols, ", :")

	safeInsert := strings.Join(safeCols, ", ")
	safeSelect := ":" + strings.Join(safeCols, ", :")

	return Columns{
		allColumns:   allCols,
		AllRaw:       allInsert,
		AllPrefixed:  allSelect,
		safeColumns:  safeCols,
		SafeRaw:      safeInsert,
		SafePrefixed: safeSelect,
	}
}
