package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	dnsapi "github.com/AS214933/derpers-contorller/internal/dns"
	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"github.com/jackc/pgx/v5"
)

func domain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if len(p) == 0 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, c := range p {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}
func within(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }
func validateDNS(n model.DNSAccount, s map[string]string) error {
	if n.Name == "" || !domain(n.Zone) || !domain(n.Suffix) || !within(n.Suffix, n.Zone) {
		return errors.New("name, valid DNS zone, and a suffix within that zone are required")
	}
	return dnsapi.Credentials(n.Provider, s)
}
func (a *App) dnsAccount(ctx context.Context, id string) (model.DNSAccount, map[string]string, error) {
	r, e := a.Store.Get(ctx, "dns", id)
	if e != nil {
		return model.DNSAccount{}, nil, e
	}
	n, e := store.Decode[model.DNSAccount](r)
	if e != nil {
		return n, nil, e
	}
	s, e := a.Store.Secrets(r)
	return n, s, e
}
func testDNS(ctx context.Context, n model.DNSAccount, s map[string]string) error {
	p, e := dnsapi.New(n.Provider, n.Zone, s)
	if e != nil {
		return e
	}
	_, e = p.List(ctx, n.Zone)
	if e != nil {
		return errors.New("DNS account read test failed; check zone and API permissions")
	}
	return nil
}
func (a *App) dnsAPI(w http.ResponseWriter, r *http.Request, u model.User, parts []string) {
	ctx := r.Context()
	if len(parts) == 0 && r.Method == "GET" {
		rs, e := a.Store.List(ctx, "dns", "")
		if e != nil {
			failure(w, 503, "DNS accounts unavailable")
			return
		}
		out := []model.DNSAccount{}
		for _, rec := range rs {
			n, e := store.Decode[model.DNSAccount](rec)
			if e != nil {
				failure(w, 503, "invalid DNS account")
				return
			}
			out = append(out, n)
		}
		jsonResponse(w, 200, out)
		return
	}
	var old model.DNSAccount
	var rec store.Record
	var e error
	if len(parts) > 0 {
		rec, e = a.Store.Get(ctx, "dns", parts[0])
		if e != nil {
			apiError(w, e)
			return
		}
		old, e = store.Decode[model.DNSAccount](rec)
		if e != nil {
			apiError(w, e)
			return
		}
	}
	if len(parts) == 1 && r.Method == "GET" {
		jsonResponse(w, 200, old)
		return
	}
	if len(parts) == 0 && r.Method == "POST" || len(parts) == 1 && r.Method == "PUT" {
		var v struct {
			model.DNSAccount
			Credentials map[string]string `json:"credentials"`
		}
		if e = body(r, &v); e != nil {
			apiError(w, e)
			return
		}
		n := v.DNSAccount
		n.Zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n.Zone), "."))
		n.Suffix = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n.Suffix), "."))
		s := v.Credentials
		if s == nil {
			s = map[string]string{}
		}
		if old.ID != "" {
			prev, e := a.Store.Secrets(rec)
			if e != nil {
				failure(w, 503, "credentials unavailable")
				return
			}
			for k, x := range prev {
				if s[k] == "" {
					s[k] = x
				}
			}
			if old.Provider != n.Provider || old.Zone != n.Zone {
				failure(w, 409, "provider and zone are immutable; create a new DNS account")
				return
			}
		}
		if e = validateDNS(n, s); e != nil {
			apiError(w, e)
			return
		}
		if e = testDNS(ctx, n, s); e != nil {
			apiError(w, e)
			return
		}
		rev := rec.Revision + 1
		n.ID = old.ID
		if n.ID == "" {
			n.ID = store.ID()
			rev = 1
		}
		n.Health = "healthy"
		n.LastError = ""
		if e = a.Store.Save(ctx, "dns", n.ID, "", rev, n, s); e != nil {
			apiError(w, e)
			return
		}
		a.event(ctx, "dns_account_saved", u.ID, "", "", "DNS account tested and saved")
		jsonResponse(w, 200, n)
		return
	}
	if len(parts) == 1 && r.Method == "DELETE" {
		rs, e := a.Store.List(ctx, "node", "")
		if e != nil {
			apiError(w, e)
			return
		}
		for _, r := range rs {
			n, _ := store.Decode[model.Node](r)
			if n.DNSAccountID == old.ID {
				failure(w, 409, "DNS account is assigned to a node")
				return
			}
		}
		var count int
		e = a.Store.Pool.QueryRow(ctx, "SELECT count(*) FROM dns_records WHERE account_id=$1", old.ID).Scan(&count)
		if e != nil {
			apiError(w, e)
			return
		}
		if count != 0 {
			failure(w, 409, "remove owned records before deleting the account")
			return
		}
		if e = a.Store.Delete(ctx, "dns", old.ID); e != nil {
			apiError(w, e)
			return
		}
		a.event(ctx, "dns_account_deleted", u.ID, "", "", old.ID)
		jsonResponse(w, 204, nil)
		return
	}
	if len(parts) == 2 && parts[1] == "test" && r.Method == "POST" {
		s, e := a.Store.Secrets(rec)
		if e == nil {
			e = testDNS(ctx, old, s)
		}
		if e != nil {
			_ = a.Store.Patch(ctx, "dns", old.ID, rec.Revision, map[string]string{"health": "degraded", "last_error": "DNS account test failed"})
			apiError(w, e)
			return
		}
		_ = a.Store.Patch(ctx, "dns", old.ID, rec.Revision, map[string]string{"health": "healthy", "last_error": ""})
		jsonResponse(w, 200, map[string]string{"status": "ok"})
		return
	}
	failure(w, 405, "unsupported DNS account operation")
}
func (a *App) ownedDNS(ctx context.Context, account, id string) ([]dnsapi.Record, error) {
	var b []byte
	e := a.Store.Pool.QueryRow(ctx, "SELECT data FROM dns_records WHERE account_id=$1 AND node_id=$2", account, id).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return []dnsapi.Record{}, nil
	}
	if e != nil {
		return nil, e
	}
	var out []dnsapi.Record
	e = json.Unmarshal(b, &out)
	return out, e
}
func (a *App) saveOwnedDNS(ctx context.Context, account, id string, rs []dnsapi.Record) error {
	b, e := json.Marshal(rs)
	if e != nil {
		return e
	}
	_, e = a.Store.Pool.Exec(ctx, "INSERT INTO dns_records(account_id,node_id,data) VALUES($1,$2,$3) ON CONFLICT(account_id,node_id) DO UPDATE SET data=excluded.data", account, id, b)
	return e
}
func desiredDNS(n model.Node) ([]dnsapi.Record, error) {
	out := []dnsapi.Record{}
	for _, v := range []struct{ kind, ip string }{{"A", n.IPv4}, {"AAAA", n.IPv6}} {
		if v.ip == "" {
			continue
		}
		ip, e := netip.ParseAddr(v.ip)
		if e != nil || ip.Is4() != (v.kind == "A") || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("invalid node IP address")
		}
		out = append(out, dnsapi.Record{Name: n.Hostname, Type: v.kind, Value: ip.String()})
	}
	if len(out) == 0 {
		return nil, errors.New("at least one IP address required for managed DNS")
	}
	return out, nil
}
func (a *App) applyDNS(ctx context.Context, n model.Node, account model.DNSAccount, sec map[string]string) error {
	if !within(n.Hostname, account.Suffix) {
		return errors.New("node hostname must be within the DNS account suffix")
	}
	desired, e := desiredDNS(n)
	if e != nil {
		return e
	}
	p, e := dnsapi.New(account.Provider, account.Zone, sec)
	if e != nil {
		return e
	}
	owned, e := a.ownedDNS(ctx, account.ID, n.ID)
	if e != nil {
		return e
	}
	current, e := p.List(ctx, n.Hostname)
	if e != nil {
		return errors.New("DNS record lookup failed")
	}
	owner := map[string]bool{}
	for _, r := range owned {
		owner[r.ID] = true
	}
	for _, r := range current {
		if (r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME") && !owner[r.ID] {
			return errors.New("DNS conflict: existing records require explicit ownership import")
		}
	}
	keep := map[string]bool{}
	for _, r := range desired {
		keep[r.Type] = true
	}
	for i := len(owned) - 1; i >= 0; i-- {
		r := owned[i]
		if !keep[r.Type] {
			for _, v := range current {
				if v.ID == r.ID {
					if v.Name != r.Name || v.Type != r.Type || v.Value != r.Value {
						return errors.New("owned DNS record was changed externally")
					}
					if e = p.Delete(ctx, r); e != nil {
						return errors.New("DNS deletion failed")
					}
				}
			}
			owned = append(owned[:i], owned[i+1:]...)
			if e = a.saveOwnedDNS(ctx, account.ID, n.ID, owned); e != nil {
				return e
			}
		}
	}
	for _, want := range desired {
		idx := -1
		for i, old := range owned {
			if old.Name == want.Name && old.Type == want.Type {
				idx = i
				for _, r := range current {
					if r.ID == old.ID {
						if r.Name != old.Name || r.Type != old.Type || r.Value != old.Value {
							return errors.New("owned DNS record was changed externally")
						}
						want.ID = old.ID
					}
				}
				break
			}
		}
		updated, e := p.Put(ctx, want)
		if e != nil {
			return errors.New("DNS record update failed; check API write permission")
		}
		if idx < 0 {
			owned = append(owned, updated)
		} else {
			owned[idx] = updated
		}
		if e = a.saveOwnedDNS(ctx, account.ID, n.ID, owned); e != nil {
			return e
		}
	}
	return nil
}

// ImportDNS is an explicit administrator migration action, never an implicit overwrite.
func (a *App) ImportDNS(ctx context.Context, id string, ids []string) error {
	rec, e := a.Store.Get(ctx, "node", id)
	if e != nil {
		return e
	}
	n, e := store.Decode[model.Node](rec)
	if e != nil {
		return e
	}
	account, sec, e := a.dnsAccount(ctx, n.DNSAccountID)
	if e != nil {
		return e
	}
	if !within(n.Hostname, account.Suffix) {
		return errors.New("hostname is outside the account suffix")
	}
	p, e := dnsapi.New(account.Provider, account.Zone, sec)
	if e != nil {
		return e
	}
	rs, e := p.List(ctx, n.Hostname)
	if e != nil {
		return errors.New("DNS lookup failed")
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	if len(wanted) == 0 {
		return errors.New("explicit record IDs required")
	}
	out, e := a.ownedDNS(ctx, account.ID, n.ID)
	if e != nil {
		return e
	}
	for _, r := range rs {
		if wanted[r.ID] {
			if r.Name != n.Hostname || r.Type != "A" && r.Type != "AAAA" {
				return errors.New("only matching node A/AAAA records may be imported")
			}
			found := false
			for _, old := range out {
				if old.ID == r.ID {
					found = true
				}
			}
			if !found {
				out = append(out, r)
			}
			delete(wanted, r.ID)
		}
	}
	if len(wanted) != 0 {
		return errors.New("some record IDs do not belong to this node hostname")
	}
	return a.saveOwnedDNS(ctx, account.ID, n.ID, out)
}
func (a *App) RemoveDNS(ctx context.Context, n model.Node) error {
	if n.DNSAccountID == "" {
		return nil
	}
	owned, e := a.ownedDNS(ctx, n.DNSAccountID, n.ID)
	if e != nil || len(owned) == 0 {
		return e
	}
	account, sec, e := a.dnsAccount(ctx, n.DNSAccountID)
	if e != nil {
		return e
	}
	p, e := dnsapi.New(account.Provider, account.Zone, sec)
	if e != nil {
		return e
	}
	for len(owned) > 0 {
		old := owned[0]
		rs, e := p.List(ctx, old.Name)
		if e != nil {
			return errors.New("DNS lookup failed")
		}
		for _, r := range rs {
			if r.ID == old.ID {
				if r.Name != old.Name || r.Type != old.Type || r.Value != old.Value {
					return errors.New("DNS record changed externally; resolve ownership before deletion")
				}
				if e = p.Delete(ctx, old); e != nil {
					return errors.New("DNS deletion failed")
				}
			}
		}
		owned = owned[1:]
		if e = a.saveOwnedDNS(ctx, account.ID, n.ID, owned); e != nil {
			return e
		}
	}
	_, e = a.Store.Pool.Exec(ctx, "DELETE FROM dns_records WHERE account_id=$1 AND node_id=$2", account.ID, n.ID)
	return e
}
