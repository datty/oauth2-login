package conf

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

const configFile = "/etc/azuread.conf"

// config define openid Connect parameters
// and setting for this module
type Config struct {
	ClientID        string   `yaml:"client-id"`
	ClientSecret    string   `yaml:"client-secret"`
	RedirectURL     string   `yaml:"redirect-url"`
	PamScopes       []string `yaml:"pam-scopes"`
	NssScopes       []string `yaml:"nss-scopes"`
	TenantID        string   `yaml:"tenant-id"`
	Domain          string   `yaml:"o365-domain"`
	SufficientRoles []string `yaml:"sufficient-roles"`
	// AllowedRoles are OS level groups which must be present on the OS before
	AllowedRoles []string `yaml:"allowed-roles"`
	CreateUser   bool     `yaml:"createuser"`
	CreateGroup  bool     `yaml:"creategroup"`
}

// ReadConfig
// need file path from yaml and return config
func ReadConfig() (*Config, error) {
	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var c Config
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal filecontent to config struct:%w", err)
	}
	return &c, nil
}
