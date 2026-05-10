package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents .blastradius.yaml user configuration.
type Config struct {
	ProductionTags    []string           `yaml:"production_tags"`
	CriticalResources []string           `yaml:"critical_resources"`
	IgnoreRules       []string           `yaml:"ignore_rules"`
	Weights           map[string]float64 `yaml:"weights"`
}

// Load reads config from path. Returns defaults if file doesn't exist.
func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		ProductionTags: []string{
			"env:prod",
			"env:production",
			"environment:prod",
			"environment:production",
		},
		Weights: map[string]float64{
			"destruction": 1.0,
			"security":    1.0,
			"network":     1.0,
			"stateful":    1.0,
		},
	}
}

// ShouldIgnoreRule checks if a rule ID is in the ignore list.
func (c *Config) ShouldIgnoreRule(ruleID string) bool {
	for _, id := range c.IgnoreRules {
		if id == ruleID {
			return true
		}
	}
	return false
}
