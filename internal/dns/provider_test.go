package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	cf "github.com/cloudflare/cloudflare-go"
	ali "github.com/go-acme/alidns-20150109/v4/client"
	tc "github.com/go-acme/tencentclouddnspod/v20210323"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

// These exercise the real provider SDK request/response contracts, not a
// substitute DNS implementation. Public DNS and ACME use dedicated credentials.
func TestProviderSDKContracts(t *testing.T) {
	for _, kind := range []string{"cloudflare", "alidns", "dnspod"} {
		t.Run(kind, func(t *testing.T) {
			actions := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "cloudflare":
					if r.Header.Get("Authorization") != "Bearer test-token" {
						t.Error("SDK omitted account token")
					}
					if strings.HasSuffix(r.URL.Path, "/zones") {
						_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-1","name":"example.test","status":"active"}]}`))
						return
					}
					actions = append(actions, r.Method)
					if r.Method == "GET" {
						_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"123","name":"derp.example.test","type":"A","content":"203.0.113.10","proxied":false}],"result_info":{"page":1,"per_page":100,"total_pages":1,"count":1,"total_count":1}}`))
						return
					}
					if r.Method != "DELETE" {
						var b map[string]any
						if json.NewDecoder(r.Body).Decode(&b) != nil {
							t.Error("bad JSON")
						}
						if b["name"] != "derp.example.test" || b["type"] != "A" || b["content"] != "203.0.113.10" || b["proxied"] != false {
							t.Errorf("unsafe/wrong DNS write: %v", b)
						}
					}
					_, _ = w.Write([]byte(`{"success":true,"result":{"id":"123"}}`))
				case "alidns":
					_ = r.ParseForm()
					action := r.Form.Get("Action")
					if action == "" {
						action = r.Header.Get("x-acs-action")
					}
					actions = append(actions, action)
					if action == "DescribeDomainRecords" {
						_, _ = w.Write([]byte(`{"PageNumber":1,"PageSize":500,"TotalCount":1,"DomainRecords":{"Record":[{"RecordId":"123","RR":"derp","Type":"A","Value":"203.0.113.10"}]}}`))
						return
					}
					if action != "DeleteDomainRecord" && (r.Form.Get("RR") != "derp" || r.Form.Get("Type") != "A" || r.Form.Get("Value") != "203.0.113.10") {
						t.Errorf("incorrect AliDNS write: %s", action)
					}
					_, _ = w.Write([]byte(`{"RecordId":"123"}`))
				case "dnspod":
					action := r.Header.Get("X-TC-Action")
					actions = append(actions, action)
					var b map[string]any
					_ = json.NewDecoder(r.Body).Decode(&b)
					if action == "DescribeRecordList" {
						_, _ = w.Write([]byte(`{"Response":{"RecordList":[{"RecordId":123,"Name":"derp","Type":"A","Value":"203.0.113.10"}]}}`))
						return
					}
					if action != "DeleteRecord" && (b["SubDomain"] != "derp" || b["RecordType"] != "A" || b["Value"] != "203.0.113.10") {
						t.Errorf("incorrect DNSPod write: %v", b)
					}
					_, _ = w.Write([]byte(`{"Response":{"RecordId":123}}`))
				}
			}))
			defer server.Close()
			host, _ := url.Parse(server.URL)
			var p Provider
			switch kind {
			case "cloudflare":
				client, e := cf.NewWithAPIToken("test-token", cf.BaseURL(server.URL))
				if e != nil {
					t.Fatal(e)
				}
				p = &cloudflare{client, "example.test"}
			case "alidns":
				client, e := ali.NewClient(new(openapi.Config).SetAccessKeyId("test-id").SetAccessKeySecret("test-secret").SetEndpoint(host.Host).SetProtocol("http"))
				if e != nil {
					t.Fatal(e)
				}
				p = &alibaba{client, "example.test"}
			case "dnspod":
				profile := profile.NewClientProfile()
				profile.HttpProfile.Endpoint = host.Host
				profile.HttpProfile.Scheme = "HTTP"
				client, e := tc.NewClient(common.NewCredential("test-id", "test-secret"), "", profile)
				if e != nil {
					t.Fatal(e)
				}
				p = &tencent{client, "example.test"}
			}
			ctx := context.Background()
			rs, e := p.List(ctx, "derp.example.test")
			if e != nil {
				t.Fatal(e)
			}
			if len(rs) != 1 || rs[0].ID != "123" || rs[0].Name != "derp.example.test" {
				t.Fatalf("records=%+v", rs)
			}
			r, e := p.Put(ctx, Record{Name: "derp.example.test", Type: "A", Value: "203.0.113.10"})
			if e != nil {
				t.Fatal(e)
			}
			if r.ID != "123" {
				t.Fatal("creation ID was lost")
			}
			if _, e = p.Put(ctx, r); e != nil {
				t.Fatal(e)
			}
			if e = p.Delete(ctx, r); e != nil {
				t.Fatal(e)
			}
			if len(actions) != 4 {
				t.Fatalf("expected list/create/update/delete, got %v", actions)
			}
		})
	}
}
func TestChallengeAccountsAreIndependent(t *testing.T) {
	for _, kind := range []string{"cloudflare", "alidns", "dnspod"} {
		s := map[string]string{"api_token": "a", "access_key_id": "b", "access_key_secret": "c", "secret_id": "d", "secret_key": "e"}
		a, e := Challenge(kind, s)
		if e != nil {
			t.Fatal(e)
		}
		s["api_token"] = "second"
		s["access_key_secret"] = "second"
		s["secret_key"] = "second"
		b, e := Challenge(kind, s)
		if e != nil {
			t.Fatal(e)
		}
		if a == b {
			t.Fatal("providers shared mutable account state")
		}
	}
	if _, e := New("unsupported", "example.test", nil); e == nil {
		t.Fatal("unknown provider allowed")
	}
}
