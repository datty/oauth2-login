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
	ClientID     string `yaml:"client-id"`
	ClientSecret string `yaml:"client-secret"`
	RedirectURL  string `yaml:"redirect-url"`
	TenantID     string `yaml:"tenant-id"`
	Domain       string `yaml:"o365-domain"`
	//Used for lookup of user UID from AzureAD Custom Security Attributes
	UseSecAttributes bool   `yaml:"custom-security-attributes"`
	AttributeSet     string `yaml:"attribute-set"`
	UserUIDAttribute string `yaml:"user-uid-attribute-name"`
	UserGIDAttribute string `yaml:"user-gid-attribute-name"`
	//Should not need to change these...
	PamScopes []string `yaml:"pam-scopes"`
	NssScopes []string `yaml:"nss-scopes"`
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
