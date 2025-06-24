package repo

import (
	"context"

	"github.com/jmoiron/sqlx"
)

type RoleRepo struct {
	db *sqlx.DB
}

func NewRoleRepo(db *sqlx.DB) *RoleRepo {
	return &RoleRepo{db: db}
}

func (r *RoleRepo) GetRolesForUser(ctx context.Context, userID int64) ([]string, error) {
	// SQL: SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = $1;
	return nil, nil
}

func (r *RoleRepo) AssignRoleToUser(ctx context.Context, userID, roleID int64) error {
	// SQL: INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;
	return nil
}

func (r *RoleRepo) RemoveRoleFromUser(ctx context.Context, userID, roleID int64) error {
	// SQL: DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2;
	return nil
}

func (r *RoleRepo) CreateRole(ctx context.Context, name string) error {
	return nil
}

func (r *RoleRepo) DeleteRole(ctx context.Context, roleID int64) error {
	return nil
}
