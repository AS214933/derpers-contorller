// Package dns uses the same provider SDKs as lego, with per-account credentials.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	cf "github.com/cloudflare/cloudflare-go"
	ali "github.com/go-acme/alidns-20150109/v4/client"
	"github.com/go-acme/lego/v4/challenge"
	aali "github.com/go-acme/lego/v4/providers/dns/alidns"
	acf "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	atencent "github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	tc "github.com/go-acme/tencentclouddnspod/v20210323"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

type Record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Proxied bool   `json:"proxied,omitempty"`
}
type Provider interface {
	List(context.Context, string) ([]Record, error)
	Put(context.Context, Record) (Record, error)
	Delete(context.Context, Record) error
}

func ptr[T any](v T) *T { return &v }
func val[T any](v *T) (r T) {
	if v != nil {
		return *v
	}
	return r
}
func relative(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}
func fqdn(name, zone string) string {
	if name == "@" || name == "" {
		return zone
	}
	return name + "." + zone
}
func Credentials(kind string, s map[string]string) error {
	keys := map[string][]string{"cloudflare": {"api_token"}, "alidns": {"access_key_id", "access_key_secret"}, "dnspod": {"secret_id", "secret_key"}}
	required, ok := keys[kind]
	if !ok {
		return errors.New("unsupported DNS provider")
	}
	for _, k := range required {
		if s[k] == "" {
			return fmt.Errorf("missing credential: %s", k)
		}
	}
	return nil
}
func New(kind, zone string, s map[string]string) (Provider, error) {
	if e := Credentials(kind, s); e != nil {
		return nil, e
	}
	switch kind {
	case "cloudflare":
		c, e := cf.NewWithAPIToken(s["api_token"], cf.HTTPClient(&http.Client{Timeout: 30 * time.Second}))
		if e != nil {
			return nil, e
		}
		return &cloudflare{client: c, zone: zone}, nil
	case "alidns":
		c, e := ali.NewClient(new(openapi.Config).SetAccessKeyId(s["access_key_id"]).SetAccessKeySecret(s["access_key_secret"]).SetRegionId("cn-hangzhou").SetReadTimeout(15000).SetConnectTimeout(10000))
		if e != nil {
			return nil, e
		}
		return &alibaba{c, zone}, nil
	case "dnspod":
		p := profile.NewClientProfile()
		p.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
		p.HttpProfile.ReqTimeout = 15
		c, e := tc.NewClient(common.NewCredential(s["secret_id"], s["secret_key"]), "", p)
		if e != nil {
			return nil, e
		}
		return &tencent{c, zone}, nil
	}
	return nil, errors.New("unsupported DNS provider")
}
func Challenge(kind string, s map[string]string) (challenge.Provider, error) {
	if e := Credentials(kind, s); e != nil {
		return nil, e
	}
	switch kind {
	case "cloudflare":
		c := acf.NewDefaultConfig()
		c.AuthToken = s["api_token"]
		c.ZoneToken = s["api_token"]
		c.PropagationTimeout = 3 * time.Minute
		return acf.NewDNSProviderConfig(c)
	case "alidns":
		c := aali.NewDefaultConfig()
		c.APIKey = s["access_key_id"]
		c.SecretKey = s["access_key_secret"]
		c.PropagationTimeout = 3 * time.Minute
		return aali.NewDNSProviderConfig(c)
	case "dnspod":
		c := atencent.NewDefaultConfig()
		c.SecretID = s["secret_id"]
		c.SecretKey = s["secret_key"]
		c.PropagationTimeout = 3 * time.Minute
		return atencent.NewDNSProviderConfig(c)
	}
	return nil, errors.New("unsupported DNS provider")
}

type cloudflare struct {
	client *cf.API
	zone   string
}

func (p *cloudflare) zoneID(ctx context.Context) (string, error) {
	// ZoneIDByName uses context.Background in the SDK; use its contextual
	// equivalent so cancellation also covers discovery, before record changes.
	zones, err := p.client.ListZonesContext(ctx, cf.WithZoneFilters(p.zone, "", ""))
	if err != nil {
		return "", err
	}
	if len(zones.Result) != 1 || zones.Result[0].ID == "" {
		return "", errors.New("DNS zone was not found or is ambiguous")
	}
	return zones.Result[0].ID, nil
}
func (p *cloudflare) List(ctx context.Context, name string) ([]Record, error) {
	z, e := p.zoneID(ctx)
	if e != nil {
		return nil, e
	}
	rs, _, e := p.client.ListDNSRecords(ctx, cf.ZoneIdentifier(z), cf.ListDNSRecordsParams{Name: name})
	if e != nil {
		return nil, e
	}
	out := []Record{}
	for _, r := range rs {
		if name == "" || strings.EqualFold(r.Name, name) {
			out = append(out, Record{r.ID, r.Name, r.Type, r.Content, val(r.Proxied)})
		}
	}
	return out, nil
}
func (p *cloudflare) Put(ctx context.Context, r Record) (Record, error) {
	z, e := p.zoneID(ctx)
	if e != nil {
		return r, e
	}
	if r.ID == "" {
		v, e := p.client.CreateDNSRecord(ctx, cf.ZoneIdentifier(z), cf.CreateDNSRecordParams{Name: r.Name, Type: r.Type, Content: r.Value, TTL: 300, Proxied: ptr(false), Comment: "managed by derpers-controller"})
		r.ID = v.ID
		if e == nil && r.ID == "" {
			e = errors.New("Cloudflare returned no DNS record ID")
		}
		return r, e
	}
	_, e = p.client.UpdateDNSRecord(ctx, cf.ZoneIdentifier(z), cf.UpdateDNSRecordParams{ID: r.ID, Name: r.Name, Type: r.Type, Content: r.Value, TTL: 300, Proxied: ptr(false)})
	return r, e
}
func (p *cloudflare) Delete(ctx context.Context, r Record) error {
	z, e := p.zoneID(ctx)
	if e != nil {
		return e
	}
	return p.client.DeleteDNSRecord(ctx, cf.ZoneIdentifier(z), r.ID)
}

type alibaba struct {
	client *ali.Client
	zone   string
}

func (p *alibaba) List(ctx context.Context, name string) ([]Record, error) {
	out := []Record{}
	for page := int64(1); ; page++ {
		q := new(ali.DescribeDomainRecordsRequest).SetDomainName(p.zone).SetPageSize(500).SetPageNumber(page)
		if name != "" {
			q.SetRRKeyWord(relative(name, p.zone))
		}
		res, e := ali.DescribeDomainRecordsWithContext(ctx, p.client, q, &dara.RuntimeOptions{})
		if e != nil {
			return nil, e
		}
		if res == nil || res.Body == nil || res.Body.DomainRecords == nil || res.Body.TotalCount == nil {
			return nil, errors.New("incomplete AliDNS response")
		}
		for _, r := range res.Body.DomainRecords.Record {
			n := fqdn(val(r.RR), p.zone)
			if name == "" || strings.EqualFold(n, name) {
				out = append(out, Record{ID: val(r.RecordId), Name: n, Type: val(r.Type), Value: val(r.Value)})
			}
		}
		if page*500 >= val(res.Body.TotalCount) {
			break
		}
	}
	return out, nil
}
func (p *alibaba) Put(ctx context.Context, r Record) (Record, error) {
	if r.ID == "" {
		res, e := ali.AddDomainRecordWithContext(ctx, p.client, new(ali.AddDomainRecordRequest).SetDomainName(p.zone).SetRR(relative(r.Name, p.zone)).SetType(r.Type).SetValue(r.Value).SetTTL(600), &dara.RuntimeOptions{})
		if e == nil {
			if res == nil || res.Body == nil || val(res.Body.RecordId) == "" {
				return r, errors.New("AliDNS returned no DNS record ID")
			}
			r.ID = val(res.Body.RecordId)
		}
		return r, e
	}
	_, e := ali.UpdateDomainRecordWithContext(ctx, p.client, new(ali.UpdateDomainRecordRequest).SetRecordId(r.ID).SetRR(relative(r.Name, p.zone)).SetType(r.Type).SetValue(r.Value).SetTTL(600), &dara.RuntimeOptions{})
	return r, e
}
func (p *alibaba) Delete(ctx context.Context, r Record) error {
	_, e := ali.DeleteDomainRecordWithContext(ctx, p.client, new(ali.DeleteDomainRecordRequest).SetRecordId(r.ID), &dara.RuntimeOptions{})
	return e
}

type tencent struct {
	client *tc.Client
	zone   string
}

func (p *tencent) List(ctx context.Context, name string) ([]Record, error) {
	out := []Record{}
	for offset := uint64(0); ; offset += 100 {
		q := tc.NewDescribeRecordListRequest()
		q.Domain = ptr(p.zone)
		q.Offset = ptr(offset)
		q.Limit = ptr(uint64(100))
		if name != "" {
			q.Subdomain = ptr(relative(name, p.zone))
		}
		res, e := tc.DescribeRecordListWithContext(ctx, p.client, q)
		if e != nil {
			var api *tcerrors.TencentCloudSDKError
			if errors.As(e, &api) && api.Code == "ResourceNotFound.NoDataOfRecord" {
				return out, nil
			}
			return nil, e
		}
		if res == nil || res.Response == nil {
			return nil, errors.New("incomplete DNSPod response")
		}
		for _, r := range res.Response.RecordList {
			n := fqdn(val(r.Name), p.zone)
			if name == "" || strings.EqualFold(name, n) {
				out = append(out, Record{ID: strconv.FormatUint(val(r.RecordId), 10), Name: n, Type: val(r.Type), Value: val(r.Value)})
			}
		}
		if len(res.Response.RecordList) < 100 {
			break
		}
	}
	return out, nil
}
func (p *tencent) Put(ctx context.Context, r Record) (Record, error) {
	if r.ID == "" {
		q := tc.NewCreateRecordRequest()
		q.Domain = ptr(p.zone)
		q.SubDomain = ptr(relative(r.Name, p.zone))
		q.RecordType = ptr(r.Type)
		q.Value = ptr(r.Value)
		q.RecordLine = ptr("默认")
		q.TTL = ptr(uint64(600))
		res, e := tc.CreateRecordWithContext(ctx, p.client, q)
		if e == nil {
			if res == nil || res.Response == nil || val(res.Response.RecordId) == 0 {
				return r, errors.New("DNSPod returned no DNS record ID")
			}
			r.ID = strconv.FormatUint(val(res.Response.RecordId), 10)
		}
		return r, e
	}
	id, e := strconv.ParseUint(r.ID, 10, 64)
	if e != nil {
		return r, e
	}
	q := tc.NewModifyRecordRequest()
	q.Domain = ptr(p.zone)
	q.RecordId = ptr(id)
	q.SubDomain = ptr(relative(r.Name, p.zone))
	q.RecordType = ptr(r.Type)
	q.Value = ptr(r.Value)
	q.RecordLine = ptr("默认")
	q.TTL = ptr(uint64(600))
	_, e = tc.ModifyRecordWithContext(ctx, p.client, q)
	return r, e
}
func (p *tencent) Delete(ctx context.Context, r Record) error {
	id, e := strconv.ParseUint(r.ID, 10, 64)
	if e != nil {
		return e
	}
	q := tc.NewDeleteRecordRequest()
	q.Domain = ptr(p.zone)
	q.RecordId = ptr(id)
	_, e = tc.DeleteRecordWithContext(ctx, p.client, q)
	return e
}
