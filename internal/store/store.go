package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrConflict = errors.New("resource changed; reload and retry")
var ErrNotFound = errors.New("resource not found")

type Store struct {
	Pool     *pgxpool.Pool
	lockPool *pgxpool.Pool
	aead     cipher.AEAD
}
type Record struct {
	Kind, ID, Owner string
	Revision        int64
	Data            json.RawMessage
	Secret          []byte
}

func Open(ctx context.Context, url, master string) (*Store, error) {
	k, e := base64.StdEncoding.DecodeString(master)
	if e != nil || len(k) != 32 {
		return nil, errors.New("invalid encryption key")
	}
	block, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	cfg, e := pgxpool.ParseConfig(url)
	if e != nil {
		return nil, e
	}
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	lockCfg := cfg.Copy()
	lockCfg.MaxConns = 16
	lockCfg.MinConns = 0
	lockCfg.MinIdleConns = 0
	locks, e := pgxpool.NewWithConfig(ctx, lockCfg)
	if e != nil {
		p.Close()
		return nil, e
	}
	s := &Store{Pool: p, lockPool: locks, aead: a}
	return s, nil
}
func (s *Store) Close() { s.Pool.Close(); s.lockPool.Close() }

// Lock uses a dedicated session; contention is reported instead of waiting
// behind a long ACME operation. Always call release on the success path.
func (s *Store) Lock(ctx context.Context, key string) (func(), error) {
	// Advisory lock sessions never consume the connections used by admission.
	// A bounded acquire also avoids starvation when a node operation needs its
	// second, zone-scoped lock while the lock pool is already saturated.
	acquireCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	conn, e := s.lockPool.Acquire(acquireCtx)
	if e != nil {
		if ctx.Err() == nil && acquireCtx.Err() != nil {
			return nil, ErrConflict
		}
		return nil, e
	}
	var acquired bool
	e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&acquired)
	if e != nil || !acquired {
		conn.Release()
		if e == nil {
			e = ErrConflict
		}
		return nil, e
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, e := conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key); e != nil {
			_ = conn.Conn().Close(context.Background())
		}
		conn.Release()
	}, nil
}
func (s *Store) Migrate(ctx context.Context) error {
	_, e := s.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS resources(kind text NOT NULL,id text NOT NULL,owner_id text NOT NULL DEFAULT '',revision bigint NOT NULL DEFAULT 1,data jsonb NOT NULL,secret bytea,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(kind,id));
 CREATE INDEX IF NOT EXISTS resources_owner ON resources(kind,owner_id);
 CREATE UNIQUE INDEX IF NOT EXISTS node_hostname ON resources(lower(data->>'hostname')) WHERE kind='node';
 CREATE UNIQUE INDEX IF NOT EXISTS node_region ON resources((data->>'region_id')) WHERE kind='node';
 CREATE TABLE IF NOT EXISTS sessions(id text PRIMARY KEY,data bytea NOT NULL,expires timestamptz NOT NULL);
 CREATE TABLE IF NOT EXISTS enrollments(hash text PRIMARY KEY,node_id text NOT NULL,expires timestamptz NOT NULL);
 CREATE TABLE IF NOT EXISTS audit(id text PRIMARY KEY,time timestamptz NOT NULL,data jsonb NOT NULL);
 CREATE INDEX IF NOT EXISTS audit_time ON audit(time DESC);
 CREATE TABLE IF NOT EXISTS node_serials(serial text PRIMARY KEY,node_id text NOT NULL,expires timestamptz NOT NULL);
 CREATE TABLE IF NOT EXISTS dns_records(account_id text NOT NULL,node_id text NOT NULL,data jsonb NOT NULL,PRIMARY KEY(account_id,node_id));`)
	return e
}
func ID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func Token() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func Hash(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func (s *Store) Encrypt(kind, id string, plain []byte) []byte {
	n := make([]byte, s.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		panic(e)
	}
	return s.aead.Seal(n, n, plain, []byte(kind+":"+id))
}
func (s *Store) Decrypt(kind, id string, b []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(b) < n {
		return nil, errors.New("invalid ciphertext")
	}
	return s.aead.Open(nil, b[:n], b[n:], []byte(kind+":"+id))
}
func (s *Store) List(ctx context.Context, kind, owner string) ([]Record, error) {
	rows, e := s.Pool.Query(ctx, "SELECT kind,id,owner_id,revision,data,secret FROM resources WHERE kind=$1 AND ($2='' OR owner_id=$2) ORDER BY created_at,id", kind, owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		if e = rows.Scan(&r.Kind, &r.ID, &r.Owner, &r.Revision, &r.Data, &r.Secret); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) Get(ctx context.Context, kind, id string) (Record, error) {
	var r Record
	e := s.Pool.QueryRow(ctx, "SELECT kind,id,owner_id,revision,data,secret FROM resources WHERE kind=$1 AND id=$2", kind, id).Scan(&r.Kind, &r.ID, &r.Owner, &r.Revision, &r.Data, &r.Secret)
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	return r, e
}
func (s *Store) Save(ctx context.Context, kind, id, owner string, revision int64, data any, secret any) error {
	b, e := json.Marshal(data)
	if e != nil {
		return e
	}
	var encrypted []byte
	if secret != nil {
		v, x := json.Marshal(secret)
		if x != nil {
			return x
		}
		encrypted = s.Encrypt(kind, id, v)
	}
	if revision == 1 {
		if kind == "network" {
			_, e = s.Pool.Exec(ctx, `WITH changed AS (INSERT INTO resources(kind,id,owner_id,revision,data,secret) VALUES($1,$2,$3,$4,$5,$6) RETURNING id) SELECT pg_notify('derpers_network',id) FROM changed`, kind, id, owner, revision, b, encrypted)
			return e
		}
		_, e = s.Pool.Exec(ctx, "INSERT INTO resources(kind,id,owner_id,revision,data,secret) VALUES($1,$2,$3,$4,$5,$6)", kind, id, owner, revision, b, encrypted)
		return e
	}
	query := "UPDATE resources SET owner_id=$3,revision=$4,data=$5::jsonb || CASE WHEN kind='node' THEN jsonb_build_object('last_seen',data->'last_seen','applied_revision',data->'applied_revision','metrics',data->'metrics','status',data->'status') ELSE '{}'::jsonb END,secret=COALESCE($6,secret) WHERE kind=$1 AND id=$2 AND revision=$7"
	if kind == "network" {
		query = "WITH changed AS (" + query + " RETURNING id) SELECT pg_notify('derpers_network',id) FROM changed"
	}
	q, e := s.Pool.Exec(ctx, query, kind, id, owner, revision, b, encrypted, revision-1)
	if e != nil {
		return e
	}
	if q.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
func (s *Store) Patch(ctx context.Context, kind, id string, revision int64, patch any) error {
	b, e := json.Marshal(patch)
	if e != nil {
		return e
	}
	q, e := s.Pool.Exec(ctx, "UPDATE resources SET data=data || $3::jsonb WHERE kind=$1 AND id=$2 AND ($4::bigint=0 OR revision=$4)", kind, id, b, revision)
	if e == nil && q.RowsAffected() != 1 {
		return ErrConflict
	}
	return e
}
func (s *Store) QueueNodeTask(ctx context.Context, n model.Node, t model.Task) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var revision int64
	e = tx.QueryRow(ctx, "SELECT revision FROM resources WHERE kind='node' AND id=$1 FOR UPDATE", n.ID).Scan(&revision)
	if e != nil {
		return e
	}
	if t.Type == "upgrade" {
		if revision != n.Revision-1 {
			return ErrConflict
		}
		var pending int
		e = tx.QueryRow(ctx, "SELECT count(*) FROM resources WHERE kind='task' AND data->>'node_id'=$1 AND data->>'type'='upgrade' AND data->>'status'='pending'", n.ID).Scan(&pending)
		if e != nil {
			return e
		}
		if pending != 0 {
			return errors.New("another upgrade is pending for this node")
		}
		b, e := json.Marshal(n)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, "UPDATE resources SET revision=$2,data=$3::jsonb || jsonb_build_object('last_seen',data->'last_seen','applied_revision',data->'applied_revision','metrics',data->'metrics','status',data->'status') WHERE kind='node' AND id=$1", n.ID, n.Revision, b)
		if e != nil {
			return e
		}
	}
	b, e := json.Marshal(t)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO resources(kind,id,revision,data) VALUES('task',$1,1,$2)", t.ID, b)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) ReportNode(ctx context.Context, id string, v model.Report) error {
	b, e := json.Marshal(v.Metrics)
	if e != nil {
		return e
	}
	q, e := s.Pool.Exec(ctx, `UPDATE resources SET data=data || jsonb_build_object('last_seen',now(),'status',CASE WHEN $2::bigint>=COALESCE((data->>'applied_revision')::bigint,0) THEN $3 ELSE data->>'status' END,'applied_revision',GREATEST(COALESCE((data->>'applied_revision')::bigint,0),$2::bigint),'metrics',$4::jsonb) WHERE kind='node' AND id=$1 AND $2::bigint<=revision`, id, v.Revision, v.Status, b)
	if e == nil && q.RowsAffected() != 1 {
		return ErrConflict
	}
	return e
}
func (s *Store) CompleteNodeTask(ctx context.Context, t model.Task, result model.TaskResult) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var data []byte
	e = tx.QueryRow(ctx, "SELECT data FROM resources WHERE kind='task' AND id=$1 FOR UPDATE", t.ID).Scan(&data)
	if e != nil {
		return e
	}
	var current model.Task
	if e = json.Unmarshal(data, &current); e != nil {
		return e
	}
	if current.Status != "pending" {
		return nil
	}
	if t.Type == "upgrade" && (result.Status == "failed" || result.Status == "rolled_back") {
		var p struct {
			Component string `json:"component"`
			Image     string `json:"image"`
			Previous  string `json:"previous_image"`
		}
		if e = json.Unmarshal(t.Payload, &p); e != nil {
			return e
		}
		field := "derper_image"
		if p.Component == "caddy" {
			field = "caddy_image"
		}
		if p.Previous == "" {
			return errors.New("upgrade is missing its rollback image")
		}
		_, e = tx.Exec(ctx, `UPDATE resources SET revision=revision+1,data=data || jsonb_build_object($2::text,$3::text,'revision',revision+1) WHERE kind='node' AND id=$1 AND data->>$2=$4`, t.NodeID, field, p.Previous, p.Image)
		if e != nil {
			return e
		}
	}
	current.Status = result.Status
	current.Message = result.Message
	current.Logs = result.Logs
	data, e = json.Marshal(current)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "UPDATE resources SET data=$2 WHERE kind='task' AND id=$1", t.ID, data)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) Delete(ctx context.Context, kind, id string) error {
	query := "DELETE FROM resources WHERE kind=$1 AND id=$2"
	if kind == "network" {
		query = "WITH removed AS (" + query + " RETURNING id) SELECT pg_notify('derpers_network',id) FROM removed"
	}
	q, e := s.Pool.Exec(ctx, query, kind, id)
	if e == nil && q.RowsAffected() == 0 {
		return ErrNotFound
	}
	return e
}
func Decode[T any](r Record) (T, error) { var v T; e := json.Unmarshal(r.Data, &v); return v, e }
func (s *Store) Secrets(r Record) (map[string]string, error) {
	if len(r.Secret) == 0 {
		return map[string]string{}, nil
	}
	b, e := s.Decrypt(r.Kind, r.ID, r.Secret)
	if e != nil {
		return nil, e
	}
	m := map[string]string{}
	e = json.Unmarshal(b, &m)
	return m, e
}
func (s *Store) Audit(ctx context.Context, a model.Audit) error {
	if a.ID == "" {
		a.ID = ID()
	}
	a.Time = time.Now().UTC()
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	_, e = s.Pool.Exec(ctx, "INSERT INTO audit(id,time,data) VALUES($1,$2,$3)", a.ID, a.Time, b)
	return e
}
func (s *Store) Audits(ctx context.Context) ([]model.Audit, error) {
	rows, e := s.Pool.Query(ctx, "SELECT data FROM audit ORDER BY time DESC LIMIT 500")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Audit{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		var a model.Audit
		if e = json.Unmarshal(b, &a); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) SetSession(ctx context.Context, id string, v any, ttl time.Duration) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = s.Pool.Exec(ctx, "INSERT INTO sessions(id,data,expires) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=excluded.data,expires=excluded.expires", Hash(id), s.Encrypt("session", Hash(id), b), time.Now().Add(ttl))
	return e
}
func (s *Store) Session(ctx context.Context, id string, v any, consume bool) error {
	q := "SELECT data FROM sessions WHERE id=$1 AND expires>now()"
	if consume {
		q = "DELETE FROM sessions WHERE id=$1 AND expires>now() RETURNING data"
	}
	var b []byte
	e := s.Pool.QueryRow(ctx, q, Hash(id)).Scan(&b)
	if e != nil {
		return e
	}
	p, e := s.Decrypt("session", Hash(id), b)
	if e != nil {
		return e
	}
	return json.Unmarshal(p, v)
}
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, e := s.Pool.Exec(ctx, "DELETE FROM sessions WHERE id=$1", Hash(id))
	return e
}
func (s *Store) NewEnrollment(ctx context.Context, nodeID string) (string, error) {
	t := Token()
	_, e := s.Pool.Exec(ctx, "INSERT INTO enrollments(hash,node_id,expires) VALUES($1,$2,$3)", Hash(t), nodeID, time.Now().Add(10*time.Minute))
	return t, e
}
func (s *Store) ConsumeEnrollment(ctx context.Context, t string) (string, error) {
	var id string
	e := s.Pool.QueryRow(ctx, "DELETE FROM enrollments WHERE hash=$1 AND expires>now() RETURNING node_id", Hash(t)).Scan(&id)
	if e != nil {
		return "", fmt.Errorf("invalid or expired enrollment token")
	}
	return id, nil
}
func (s *Store) Cleanup(ctx context.Context) error {
	_, e := s.Pool.Exec(ctx, "DELETE FROM sessions WHERE expires<now(); DELETE FROM enrollments WHERE expires<now(); DELETE FROM node_serials WHERE expires<now(); DELETE FROM audit WHERE time<now()-interval '30 days'")
	return e
}
