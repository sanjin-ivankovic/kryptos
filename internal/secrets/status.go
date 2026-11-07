package secrets

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
)

// SecretStatus is one config secret checked against its sealed file.
type SecretStatus struct {
	App          string   `json:"app"`
	Secret       string   `json:"secret"`
	File         string   `json:"file"`
	Sealed       bool     `json:"sealed"`
	MissingKeys  []string `json:"missing_keys,omitempty"`
	OrphanedKeys []string `json:"orphaned_keys,omitempty"`
	Immutable    []string `json:"immutable,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// Problem reports whether this secret needs attention.
func (s SecretStatus) Problem() bool {
	return !s.Sealed || s.Error != "" || len(s.MissingKeys) > 0 || len(s.OrphanedKeys) > 0
}

// ConfigProblem is a config file that does not load or does not validate.
type ConfigProblem struct {
	File   string   `json:"file"`
	Errors []string `json:"errors"`
}

// Status is the repo-wide health report behind `kryptos status`: what validate,
// audit and diff check, in one structure. It reads only the repo.
type Status struct {
	OK             bool            `json:"ok"`
	Problems       int             `json:"problems"`
	Configs        int             `json:"configs"`
	Secrets        []SecretStatus  `json:"secrets"`
	InvalidConfigs []ConfigProblem `json:"invalid_configs,omitempty"`
	OrphanedFiles  []string        `json:"orphaned_files,omitempty"`
}

// BuildStatus checks every config in layout against the sealed files on disk.
func BuildStatus(layout *config.Layout) (*Status, error) {
	files, err := config.ListConfigs(layout.ConfigDir)
	if err != nil {
		return nil, err
	}
	st := &Status{Configs: len(files), Secrets: []SecretStatus{}}
	for _, file := range files {
		app, err := config.LoadConfig(file)
		if err != nil {
			st.InvalidConfigs = append(st.InvalidConfigs, ConfigProblem{File: filepath.Base(file), Errors: []string{err.Error()}})
			continue
		}
		if verrs := config.Validate(app); len(verrs) > 0 {
			p := ConfigProblem{File: filepath.Base(file)}
			for _, e := range verrs {
				p.Errors = append(p.Errors, e.Error())
			}
			st.InvalidConfigs = append(st.InvalidConfigs, p)
		}
		statusApp(layout, app, st)
	}

	for _, p := range st.InvalidConfigs {
		st.Problems += len(p.Errors)
	}
	for _, s := range st.Secrets {
		if s.Problem() {
			st.Problems++
		}
	}
	st.Problems += len(st.OrphanedFiles)
	st.OK = st.Problems == 0
	return st, nil
}

func statusApp(layout *config.Layout, app *config.AppConfig, st *Status) {
	dir, dirErr := layout.SecretsDirReadOnly(app.AppName)
	expected := make(map[string]bool, len(app.Secrets))
	for i := range app.Secrets {
		secret := &app.Secrets[i]
		name := SealedFilenameFor(secret)
		expected[name] = true
		s := SecretStatus{App: app.AppName, Secret: secret.Name, File: name}
		for _, f := range secret.Fields {
			if f.Immutable {
				s.Immutable = append(s.Immutable, f.Name)
			}
		}
		if dirErr != nil {
			s.Error = dirErr.Error()
			st.Secrets = append(st.Secrets, s)
			continue
		}
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			st.Secrets = append(st.Secrets, s)
			continue
		}
		s.Sealed = true
		want, err := ExpectedKeys(app, secret)
		if err != nil {
			s.Error = err.Error()
		} else if have, err := SealedKeys(path); err != nil {
			s.Error = err.Error()
		} else {
			s.MissingKeys, s.OrphanedKeys = DiffKeys(want, have)
		}
		st.Secrets = append(st.Secrets, s)
	}
	if dirErr == nil {
		for _, orphan := range OrphanedSealedFiles(dir, expected) {
			st.OrphanedFiles = append(st.OrphanedFiles, app.AppName+"/"+orphan)
		}
	}
}

// OrphanedSealedFiles returns the *-sealed-secret.yaml files in dir that are not
// in the expected set, sorted.
func OrphanedSealedFiles(dir string, expected map[string]bool) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var orphans []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "-sealed-secret.yaml") || expected[name] {
			continue
		}
		orphans = append(orphans, name)
	}
	sort.Strings(orphans)
	return orphans
}
