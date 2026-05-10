package rules

import (
	"embed"
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed definitions/*.yaml
var embeddedRules embed.FS

// LoadEmbedded loads all built-in YAML rule files.
func LoadEmbedded() ([]Rule, error) {
	entries, err := embeddedRules.ReadDir("definitions")
	if err != nil {
		return nil, fmt.Errorf("read embedded rules dir: %w", err)
	}

	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := embeddedRules.ReadFile("definitions/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var rules []Rule
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		allRules = append(allRules, rules...)
	}
	return allRules, nil
}
