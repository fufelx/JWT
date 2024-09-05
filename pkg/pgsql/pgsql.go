package pgsql

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v4/pgxpool"
)

type Claims struct {
	UserID string `json:"user_id"`
	IP     string `json:"ip"`
	jwt.RegisteredClaims
}

type Store struct {
	ctx context.Context
	db  pgxpool.Pool
}

func New() (*Store, error) {
	var ctx context.Context = context.Background()
	db, err := pgxpool.Connect(ctx, "postgres://log:pass@ip/dbname")
	if err != nil {
		return nil, err
	}
	result := Store{ctx: ctx, db: *db}
	return &result, nil
}

func (s *Store) AddUser(id int64, ip, refreshToken string) error {
	tx, err := s.db.Begin(s.ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(s.ctx)

	_, err = tx.Exec(s.ctx, `INSERT INTO users(id, ip, refreshtoken) VALUES ($1,$2,$3)`, id, ip, refreshToken)
	if err != nil {
		return err
	} else {
		tx.Commit(s.ctx)
		return nil
	}
}

func (s *Store) UserInfo(id int64) (refreshtoken string, err error) {
	rows, err := s.db.Query(s.ctx, `SELECT refreshtoken FROM users WHERE id = $1`, id)
	if err != nil {
		return "", err
	} else {
		for rows.Next() {
			var refreshtoken1 string
			rows.Scan(&refreshtoken1)
			return refreshtoken1, nil
		}
		return "", nil
	}
}
func (s *Store) UpdateUser(id int64, refreshtoken string) error {
	tx, err := s.db.Begin(s.ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(s.ctx)
	_, err = tx.Exec(s.ctx, `UPDATE users SET
			refreshtoken = $1
		    WHERE id = $2`, refreshtoken, id)
	if err != nil {
		return err
	} else {
		tx.Commit(s.ctx)
		return nil
	}
}
