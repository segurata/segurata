package liveness

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
)

// AWS: sts:GetCallerIdentity, which needs no IAM permission and cannot be denied, through the
// Query API as a GET signed with Signature Version 4 by hand (standard library only). Only 200
// tells: 403 InvalidClientTokenId is also the global endpoint's answer to a key of the GovCloud or
// China partitions, and SignatureDoesNotMatch says the pair found in the file is not a pair.

const (
	stsQuery   = "Action=GetCallerIdentity&Version=2011-06-15"
	stsRegion  = "us-east-1"
	stsService = "sts"
)

var (
	awsErrorCode = regexp.MustCompile(`<Code>([A-Za-z]+)</Code>|"Code"\s*:\s*"([A-Za-z]+)"`)
	awsAccount   = regexp.MustCompile(`<Account>(\d{12})</Account>|"Account"\s*:\s*"(\d{12})"`)
)

func askAWS(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	u, err := url.Parse(base)
	if err != nil {
		return secretrisk.Liveness{State: secretrisk.Unknown, Reason: "bad endpoint"}
	}
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		if c := firstGroup(awsErrorCode, body); code != http.StatusOK && c != "" {
			return secretrisk.Unknown, c
		}
		return byStatus(false)(code, body)
	}
	acct := func(body []byte) string {
		if a := firstGroup(awsAccount, body); a != "" {
			return "aws:" + a
		}
		return ""
	}
	h := sigV4(stsQuery, u.Host, stsRegion, stsService, p.KeyID, p.Value, time.Now().UTC())
	return call(ctx, base, "/?"+stsQuery, h, j, acct)
}

// firstGroup is the first non-empty group of re's first match in body, through providerText.
func firstGroup(re *regexp.Regexp, body []byte) string {
	m := re.FindSubmatch(body)
	for i := 1; i < len(m); i++ {
		if len(m[i]) > 0 {
			return providerText(string(m[i]))
		}
	}
	return ""
}

// sigV4 signs GET /?<query> (query already in canonical order) for host, region and service at t,
// and returns the headers to send. See AWS's "Create a signed AWS API request" (Signature Version
// 4), https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html.
func sigV4(query, host, region, service, keyID, secret string, t time.Time) http.Header {
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	canonical := strings.Join([]string{
		http.MethodGet, "/", query,
		"host:" + host, "x-amz-date:" + amzDate, "",
		"host;x-amz-date", hexSHA256(""),
	}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hexSHA256(canonical)}, "\n")
	key := []byte("AWS4" + secret)
	for _, part := range []string{day, region, service, "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	return http.Header{
		"X-Amz-Date":    {amzDate},
		"Authorization": {"AWS4-HMAC-SHA256 Credential=" + keyID + "/" + scope + ", SignedHeaders=host;x-amz-date, Signature=" + sig},
	}
}

func hexSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}
