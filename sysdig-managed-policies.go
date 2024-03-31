package main

import (
	"SysdigManagedPolicies/types/config"
	"SysdigManagedPolicies/types/policies"
	"SysdigManagedPolicies/types/sysdighttp"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"net/http"
	"os"
)

func init() {
	// Set the formatter to text
	log.SetFormatter(&log.TextFormatter{
		// Disable timestamp to closely match standard log package output
		DisableTimestamp: false,
		// FullTimestamp ensures the full timestamp is printed
		FullTimestamp: true,
		// Force formatting to be the same regardless of environment
		ForceColors:            true,
		DisableLevelTruncation: true,
		// You can also modify the timestamp format to your liking
		TimestampFormat: "2006-01-02 15:04:05.000",
	})
}
func createPolicy(sysdigAPIEndpoint string, sysdigAPIToken string, policy policies.Policy, policyName string) (*http.Response, error) {
	configPolicy := sysdighttp.DefaultSysdigRequestConfig()
	configPolicy.Method = "POST"
	configPolicy.URL = fmt.Sprintf("%s/api/v2/policies", sysdigAPIEndpoint)
	configPolicy.Verify = false
	configPolicy.MaxRetries = 0
	configPolicy.Headers = map[string]string{
		"Authorization": fmt.Sprintf("bearer %s", sysdigAPIToken),
		"Content-Type":  "application/json",
	}

	policy.Name = policyName
	configPolicy.JSON = policy

	objResponse, err := sysdighttp.SysdigRequest(configPolicy)
	return objResponse, err
}

func parseAndValidateParameters() (configuration config.Config, err error) {
	pflag.BoolVarP(&configuration.Enabled, "enabled", "e", false, "Enable Policies")
	pflag.StringVarP(&configuration.SysdigAPIEndpoint, "sysdig-api-endpoint", "a", os.Getenv("SYSDIG_API_ENDPOINT"), "Sysdig API Endpoint")
	pflag.StringVarP(&configuration.SysdigAPIToken, "secure-api-token", "k", os.Getenv("SECURE_API_TOKEN"), "Sysdig API Token")
	pflag.StringVarP(&configuration.PolicyPrefix, "prefix", "p", "", "Sysdig Policy Prefix")
	pflag.StringVarP(&configuration.PolicySuffix, "suffix", "s", "", "Sysdig Policy Suffix")

	pflag.Parse()

	if configuration.SysdigAPIEndpoint == "" || configuration.SysdigAPIToken == "" {
		err = errors.New("sysdig API token or endpoint not provided, cannot continue")
		return configuration, err
	}

	return configuration, nil
}

var VERSION string

func main() {
	var err error

	managedSaaSPolicies := []policies.Policy{
		policies.SysdigRuntimeThreatIntelligence,
		policies.SysdigRuntimeThreatDetection,
		policies.SysdigRuntimeNotableEvents,
		policies.SysdigRuntimeActivityLogs,
	}

	var configuration config.Config
	if configuration, err = parseAndValidateParameters(); err != nil {
		log.Fatalf("main:: Error %v", err)
	}

	log.Printf("main:: Sysdig Managed Policy Importer - Falco Rules v1.141.1-%s", VERSION)
	for _, policy := range managedSaaSPolicies {
		policy.Enabled = configuration.Enabled
		var policyName = fmt.Sprintf("%s%s%s", configuration.PolicyPrefix, policy.Name, configuration.PolicySuffix)
		if objResponse, err := createPolicy(configuration.SysdigAPIEndpoint, configuration.SysdigAPIToken, policy, policyName); err != nil {
			if objResponse != nil {
				log.Printf("main:: Error creating Policy '%s'. Status '%d', Error: %v", policyName, objResponse.StatusCode, err)
			} else {
				log.Printf("main:: Error creating Policy '%s', Error: %v", policyName, err)
			}
		} else {
			log.Printf("main:: Created Policy '%s'. Policy Enabled?: '%t', HTTP Status '%d'", policyName, policy.Enabled, objResponse.StatusCode)
		}
	}
	log.Print("main:: Finished...")
}
