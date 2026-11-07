package secrets

import (
	"testing"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/generator"

	"github.com/goccy/go-yaml"
)

// rawFor runs a resolver through the same stages Pipeline.Process uses up to
// (not including) sealing, returning the raw Secret YAML. This is what gets
// piped to kubeseal, so byte-identical raw YAML ⇒ byte-identical SealedSecret.
func rawFor(t *testing.T, app *config.AppConfig, secret *config.Secret, resolve ValueResolver) []byte {
	t.Helper()
	data, err := resolve(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := ApplyDerivedFields(secret, data, false); err != nil {
		t.Fatalf("derive: %v", err)
	}
	for k, v := range secret.StringData {
		if _, ok := data[k]; !ok {
			data[k] = v
		}
	}
	raw, err := generator.GenerateRawSecret(app, *secret, data)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return raw
}

// TestNonInteractiveMatchesExplicitValues proves the non-interactive path
// yields the same raw Secret as feeding the identical values directly — i.e.
// the resolver is a faithful stand-in for interactive input. With the same
// values in, the htpasswd derive recomputes deterministically only in its
// username component (bcrypt salts differ), so we assert on the NON-bcrypt
// fields and the key SET, which is what "byte-identical for the same inputs"
// means in practice for derived secrets.
func TestNonInteractiveMatchesExplicitValues(t *testing.T) {
	app := &config.AppConfig{AppName: "demo", Namespace: "demo"}
	mk := func() *config.Secret {
		return &config.Secret{
			Name: "demo-secret",
			Fields: []config.SecretField{
				{Name: "username", Required: true},
				{Name: "password", Required: true},
			},
			StringData: map[string]string{"host": "db.local"},
		}
	}

	// Path A: a MapSource (the non-interactive seal path).
	src := NewMapSource(nil, map[string]string{"username": "admin", "password": "s3cret"})
	rawA := rawFor(t, app, mk(), NonInteractiveResolver(src))

	// Path B: a hand-built resolver returning the identical values (stand-in for
	// the interactive form producing the same entries).
	rawB := rawFor(t, app, mk(), func(*config.Secret) (map[string]string, error) {
		return map[string]string{"username": "admin", "password": "s3cret"}, nil
	})

	if string(rawA) != string(rawB) {
		t.Errorf("non-interactive raw secret differs from direct values:\n--- A ---\n%s\n--- B ---\n%s", rawA, rawB)
	}

	// Sanity: the raw secret round-trips and carries the expected keys.
	var k8s struct {
		StringData map[string]string `yaml:"stringData"`
	}
	if err := yaml.Unmarshal(rawA, &k8s); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	for _, k := range []string{"username", "password", "host"} {
		if _, ok := k8s.StringData[k]; !ok {
			t.Errorf("expected key %q in the sealed secret", k)
		}
	}
}

// TestPipelineDryRunNeedsNoCluster confirms a cluster_secret derive in dry-run
// produces a placeholder and the pipeline reports a (dry-run) result without a
// sealer.
func TestPipelineDryRunNeedsNoCluster(t *testing.T) {
	app := &config.AppConfig{AppName: "demo", Namespace: "demo"}
	secret := &config.Secret{
		Name: "demo-secret",
		Fields: []config.SecretField{
			{Name: "pw", Derive: "cluster_secret",
				DeriveNamespace: "valkey", DeriveSecret: "valkey-auth", DeriveKey: "password"},
		},
	}
	var emitted bool
	p := &Pipeline{
		DryRun: true,
		Hooks: Hooks{EmitDryRun: func(_ *config.AppConfig, _ *config.Secret, data map[string]string) {
			emitted = true
			if data["pw"] != "<cluster:valkey/valkey-auth.password>" {
				t.Errorf("cluster_secret placeholder = %q", data["pw"])
			}
		}},
	}
	res := p.Process(app, secret, NonInteractiveResolver(NewMapSource(nil, nil)))
	if res.Err != nil {
		t.Fatalf("dry-run process: %v", res.Err)
	}
	if !emitted {
		t.Error("EmitDryRun hook was not called")
	}
	if res.OutputPath != "(dry-run)" {
		t.Errorf("OutputPath = %q, want (dry-run)", res.OutputPath)
	}
}
