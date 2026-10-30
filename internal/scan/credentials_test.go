package scan

import (
	"strings"
	"testing"
)

// SC-04 is reported at high, which makes a false positive here the most
// expensive output stathe produces: it is the finding a client checks first,
// and the credibility of the rest of the report rides on the answer.
func TestCredentialKeyMatching(t *testing.T) {
	credentials := []string{
		"DB_PASSWORD",
		"password",
		"db.password",
		"dbPassword",
		"REDIS_PASSWD",
		"API_TOKEN",
		"GITHUB_TOKEN",
		"STRIPE_API_KEY",
		"APIKEY",
		"AWS_SECRET_ACCESS_KEY",
		"TLS_PRIVATE_KEY",
		"client-secret",
		"gcp/credentials",
		"KEYSTORE_PASSPHRASE",
	}
	for _, k := range credentials {
		if !looksLikeACredentialKey(k) {
			t.Errorf("%q names a credential and has to be reported", k)
		}
	}

	notCredentials := []string{
		// The one from the first real cluster run.
		"FOO_SECRET_SCANNER_ENABLED",
		"SECRET_SCANNER_ENABLED",
		"TOKEN_REQUIRED",
		"PASSWORD_MIN_LENGTH",
		"PASSWORD_ROTATION",
		"SERVICE_ACCOUNT_NAME",
		"SERVICE_ACCOUNTS",
		"API_KEY_PATH",
		"PRIVATE_KEY_FILE",
		"TOKEN_TTL",
		"SECRET_PROVIDER",
		"CREDENTIALS_TYPE",
		"log.level",
		"REPLICAS",
	}
	for _, k := range notCredentials {
		if looksLikeACredentialKey(k) {
			t.Errorf("%q does not name a credential; a high-severity false positive here "+
				"costs more credibility than the finding is worth", k)
		}
	}
}

func TestPlainCredentialsReportsTheKeyNamesItMatched(t *testing.T) {
	cm := Resource{
		Kind:     "ConfigMap",
		Metadata: Metadata{Name: "app-config", Namespace: "shop"},
		Data: map[string]string{
			"DB_PASSWORD":            "",
			"SECRET_SCANNER_ENABLED": "",
			"LOG_LEVEL":              "",
			"STRIPE_API_KEY":         "",
			"PASSWORD_MIN_LENGTH":    "",
			"SERVICE_ACCOUNT_NAME":   "",
		},
	}

	got := CheckPlainCredentials([]Resource{cm})
	if len(got) != 1 {
		t.Fatalf("expected one finding for the ConfigMap, got %d", len(got))
	}

	detail := got[0].Detail
	for _, want := range []string{"DB_PASSWORD", "STRIPE_API_KEY"} {
		if !strings.Contains(detail, want) {
			t.Errorf("expected %s to be named in %q", want, detail)
		}
	}
	for _, unwanted := range []string{"SECRET_SCANNER_ENABLED", "PASSWORD_MIN_LENGTH", "SERVICE_ACCOUNT_NAME", "LOG_LEVEL"} {
		if strings.Contains(detail, unwanted) {
			t.Errorf("%s is not a credential and must not appear in %q", unwanted, detail)
		}
	}
}
