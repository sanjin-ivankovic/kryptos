package config

import (
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"text/template/parse"
)

// dns1123Subdomain matches a valid Kubernetes resource name (RFC 1123): lower
// alphanumerics and '-', starting and ending alphanumeric, '.' allowed between
// labels. Secret names must satisfy this or the apiserver rejects them.
var dns1123Subdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// validGenerators is the set of generator keywords generateFieldValue knows.
// Kept in sync with internal/tui/derive_runner.go's switch.
var validGenerators = map[string]bool{
	"secure": true, "strong": true, "apikey": true, "passphrase": true,
}

// validDeriveTypes is the set of derive directives ApplyDerivedFields handles.
// Kept in sync with internal/secrets/derive.go.
var validDeriveTypes = map[string]bool{
	"htpasswd": true, "cluster_secret": true, "render": true,
	"jwt_secret": true, "hmac": true, "tls": true, "ssh_keypair": true, "file": true,
}

// magicKeywords are the "@keyword" default values expandable to a generated
// value. The template documents @secure/@strong/@apikey/@passphrase.
var magicKeywords = map[string]bool{
	"@secure": true, "@strong": true, "@apikey": true, "@passphrase": true,
}

// Validate checks an AppConfig for the problems that would make `kryptos`
// fail at generation time, and returns ALL of them (collect-all, not
// fail-fast) so a CI run surfaces every issue in one pass. A nil/empty slice
// means the config is valid.
//
// The derive checks deliberately mirror applyDerivedFields so `validate`
// rejects exactly what generation would reject — without needing a cluster.
func Validate(app *AppConfig) []error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if strings.TrimSpace(app.AppName) == "" {
		add("metadata.name (app name) must not be empty")
	}
	if strings.TrimSpace(app.Namespace) == "" {
		add("app %q: metadata.namespace must not be empty", app.AppName)
	}
	if len(app.Secrets) == 0 {
		add("app %q: defines no secrets", app.AppName)
	}

	seenSecret := make(map[string]bool, len(app.Secrets))
	for i := range app.Secrets {
		secret := app.Secrets[i]
		label := secret.Name
		if label == "" {
			label = fmt.Sprintf("secret #%d", i+1)
		}

		switch {
		case strings.TrimSpace(secret.Name) == "":
			add("app %q: %s has an empty name", app.AppName, label)
		case !dns1123Subdomain.MatchString(secret.Name):
			add("app %q: secret %q is not a valid DNS-1123 name", app.AppName, secret.Name)
		}
		if secret.Name != "" {
			if seenSecret[secret.Name] {
				add("app %q: duplicate secret name %q", app.AppName, secret.Name)
			}
			seenSecret[secret.Name] = true
		}

		validateSecretType(add, app.AppName, secret)
		validateFields(add, app.AppName, secret)
	}

	return errs
}

// validateSecretType checks the Type field and dockerconfigjson's required
// inputs.
func validateSecretType(add func(string, ...any), appName string, secret Secret) {
	switch secret.Type {
	case "", "Opaque":
		// fine
	case "kubernetes.io/dockerconfigjson":
		// generateDockerConfigJSON requires username + password to be present
		// as fields (or it errors at generation). Check the inputs exist.
		if !hasField(secret, "username") || !hasField(secret, "password") {
			add("app %q: secret %q is dockerconfigjson but is missing a username and/or password field",
				appName, secret.Name)
		}
	default:
		add("app %q: secret %q has unsupported type %q (want Opaque or kubernetes.io/dockerconfigjson)",
			appName, secret.Name, secret.Type)
	}
}

// validateFields checks per-field constraints: unique names, valid generator,
// magic-default sanity, and derive integrity (mirroring applyDerivedFields).
func validateFields(add func(string, ...any), appName string, secret Secret) {
	// Build the set of sibling field names up front so derive references can be
	// resolved regardless of declaration order (applyDerivedFields runs render
	// in a second pass, so a render template may reference a later field).
	fieldNames := make(map[string]bool, len(secret.Fields))
	for _, f := range secret.Fields {
		fieldNames[f.Name] = true
	}

	seenField := make(map[string]bool, len(secret.Fields))
	for _, f := range secret.Fields {
		ref := fmt.Sprintf("app %q secret %q field %q", appName, secret.Name, f.Name)

		if strings.TrimSpace(f.Name) == "" {
			add("app %q: secret %q has a field with an empty name", appName, secret.Name)
			continue
		}
		if seenField[f.Name] {
			add("%s: duplicate field name", ref)
		}
		seenField[f.Name] = true

		if f.Generator != "" && !validGenerators[f.Generator] {
			add("%s: unknown generator %q (want: secure, strong, apikey, passphrase)", ref, f.Generator)
		}

		// A default that looks like a magic keyword but isn't a known one is
		// almost certainly a typo (e.g. "@secrue").
		if strings.HasPrefix(f.Default, "@") && !magicKeywords[f.Default] {
			add("%s: default %q looks like a magic keyword but isn't one (want: @secure, @strong, @apikey, @passphrase)",
				ref, f.Default)
		}

		if f.Derive != "" {
			validateDerive(add, ref, f, fieldNames)
		}
	}
}

// validateDerive mirrors the requirements applyDerivedFields enforces, so a
// config that passes `validate` will not fail at derive time for a structural
// reason. fieldNames is the set of all sibling field names in the secret.
func validateDerive(add func(string, ...any), ref string, f SecretField, fieldNames map[string]bool) {
	if !validDeriveTypes[f.Derive] {
		add("%s: unknown derive type %q (want: htpasswd, cluster_secret, render)", ref, f.Derive)
		return
	}

	switch f.Derive {
	case "htpasswd":
		if f.DeriveFrom == "" {
			add("%s: derive=htpasswd requires derive_from", ref)
		} else if !fieldNames[f.DeriveFrom] {
			add("%s: derive_from references %q, which is not a field in this secret", ref, f.DeriveFrom)
		}
		if f.DeriveUsername == "" {
			add("%s: derive=htpasswd requires derive_username", ref)
		}

	case "cluster_secret":
		if f.DeriveNamespace == "" {
			add("%s: derive=cluster_secret requires derive_namespace", ref)
		}
		if f.DeriveSecret == "" {
			add("%s: derive=cluster_secret requires derive_secret", ref)
		}
		if f.DeriveKey == "" {
			add("%s: derive=cluster_secret requires derive_key", ref)
		}

	case "render":
		if f.DeriveTemplate == "" {
			add("%s: derive=render requires derive_template", ref)
			return
		}
		refs, err := templateFieldRefs(f.DeriveTemplate)
		if err != nil {
			add("%s: derive_template does not parse: %v", ref, err)
			return
		}
		for _, r := range refs {
			if !fieldNames[r] {
				add("%s: derive_template references {{ .%s }}, which is not a field in this secret", ref, r)
			}
		}

	case "file":
		if f.DerivePath == "" {
			add("%s: derive=file requires derive_path", ref)
		}

	case "jwt_secret", "hmac", "tls", "ssh_keypair":
		// No required cross-field inputs: jwt_secret/hmac take an optional
		// length; tls/ssh_keypair take optional common_name/hosts/comment.
		// Their outputs land in derived sibling keys (e.g. tls → <name>.crt/
		// .key, ssh_keypair → <name>/<name>.pub), so nothing to validate here.
	}
}

// templateFieldRefs parses a render template and returns the top-level field
// names it references via {{ .name }}. It walks the parse tree rather than
// regex-matching so it agrees exactly with text/template's grammar (the same
// engine RenderTemplate uses). Only single-element field accesses on the root
// (".name") are returned — those are the sibling lookups validate cares about.
func templateFieldRefs(body string) ([]string, error) {
	t, err := template.New("validate").Option("missingkey=error").Parse(body)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var refs []string
	for _, tmpl := range t.Templates() {
		if tmpl.Tree == nil || tmpl.Root == nil {
			continue
		}
		walkTemplateNode(tmpl.Root, func(name string) {
			if !seen[name] {
				seen[name] = true
				refs = append(refs, name)
			}
		})
	}
	return refs, nil
}

// walkTemplateNode recursively visits the parse tree, invoking emit for every
// {{ .field }} reference (a FieldNode with exactly one identifier).
func walkTemplateNode(node parse.Node, emit func(string)) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			walkTemplateNode(child, emit)
		}
	case *parse.ActionNode:
		walkPipe(n.Pipe, emit)
	case *parse.IfNode:
		walkPipe(n.Pipe, emit)
		walkTemplateNode(n.List, emit)
		walkTemplateNode(n.ElseList, emit)
	case *parse.RangeNode:
		walkPipe(n.Pipe, emit)
		walkTemplateNode(n.List, emit)
		walkTemplateNode(n.ElseList, emit)
	case *parse.WithNode:
		walkPipe(n.Pipe, emit)
		walkTemplateNode(n.List, emit)
		walkTemplateNode(n.ElseList, emit)
	}
}

// walkPipe extracts {{ .field }} references from a pipeline's commands.
func walkPipe(pipe *parse.PipeNode, emit func(string)) {
	if pipe == nil {
		return
	}
	for _, cmd := range pipe.Cmds {
		for _, arg := range cmd.Args {
			if fn, ok := arg.(*parse.FieldNode); ok && len(fn.Ident) == 1 {
				emit(fn.Ident[0])
			}
		}
	}
}

// hasField reports whether the secret declares a field with the given name.
func hasField(secret Secret, name string) bool {
	for _, f := range secret.Fields {
		if f.Name == name {
			return true
		}
	}
	return false
}
