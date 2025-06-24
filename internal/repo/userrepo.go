package repo

import (
	"context"

	"github.com/akramboussanni/gocode/internal/model"
	"github.com/jmoiron/sqlx"
)

type UserRepo struct {
	db *sqlx.DB
}

func NewUserRepo(db *sqlx.DB) *UserRepo {
	return &UserRepo{db: db}
}

const userColumns = "id, username, email, password_hash, created_at"

func (r *UserRepo) CreateUser(ctx context.Context, user *model.User) error {
	query := `
        INSERT INTO users (id, username, email, password_hash, created_at, user_role)
        VALUES (:id, :username, :email, :password_hash, :created_at, :user_role)
    `
	_, err := r.db.NamedExecContext(ctx, query, user)
	return err
}

func (r *UserRepo) GetUserById(ctx context.Context, id int64) (*model.User, error) {
	var user model.User
	err := r.db.GetContext(ctx, &user, "SELECT "+userColumns+" FROM users WHERE id=$1", id)
	return &user, err
}

func (r *UserRepo) DuplicateName(ctx context.Context, username string) (bool, error) {
	var exists bool
	err := r.db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", username)
	return exists, err
}

func (r *UserRepo) DuplicateEmail(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := r.db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", email)
	return exists, err
}

func (r *UserRepo) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	err := r.db.GetContext(ctx, &user, "SELECT "+userColumns+" FROM users WHERE email=$1", email)
	return &user, err
}

func (r *UserRepo) UpdateUser(ctx context.Context, u *model.User) error {
	query := `
		UPDATE users
		SET username = :username,
		    email = :email,
		    password_hash = :password_hash,
		    created_at = :created_at
		WHERE id = :id
	`
	_, err := r.db.NamedExecContext(ctx, query, u)
	return err
}

func (r *UserRepo) DeleteUser(ctx context.Context, id int64) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}
