/*
	This utility retrieves configuration information from DNS TXT records by reverse
	resolving host IPs.
 */

package main

import (
	"net"
	"os"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"
	"github.com/wrouesnel/go.log"
	"flag"
	"fmt"
	"encoding/json"
)

const (
	OutputSimple = "simple"
	OutputOneline = "one-line"
	OutputEnv = "env"
	OutputJson = "json"
	OutputJsonPretty = "json-pretty"
)

var Version = "0.0.0-dev"

var (
	logLevel = kingpin.Flag("log-level", "Logging level").Default("info").String()
	useHostname = kingpin.Flag("use-hostname", "Use a specified hostname, rather then reverse resolving IPs.").Bool()
	hostname = kingpin.Flag("hostname", "Hostname to query as if --use-hostname. Defaults to system hostname.").String()
	output = kingpin.Flag("output-format", "Set the output format.").Default(OutputSimple).Enum(OutputSimple, OutputOneline, OutputEnv, OutputJson, OutputJsonPretty)
	requiredSuffix = kingpin.Flag("required-suffix", "If set, require all resolved parameters to end with this suffix.").String()
	shouldFail = kingpin.Flag("fail", "If a requested flag is not found, exit 1 rather then returning a blank").Default("true").Bool()
	allowMerge = kingpin.Flag("allow-merge", "Allow non-conflicting configuration from multiple domain paths to be merged. This is usually a bad idea").Bool()
	prefix = kingpin.Flag("dns-prefix", "Standard prefix appended to all tags. This is a useful shortcut to writing key.prefix a lot.").String()
	configKeys = kingpin.Arg("name", "Configuration keys to search for a TXT configuration entries. Returned in-order for \"simple\" output type.").Required().Strings()
)

func main() {
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.Version(Version)
	kingpin.Parse()

	flag.Set("log.level", *logLevel)

	// If no hostname, get the OS hostname. If that fails, then we can't really
	// do anything.
	var hostnames []string
	if *useHostname {
		if *hostname == "" {
			var err error
			*hostname, err = os.Hostname()
			if err != nil {
				log.Fatalln("No hostname specified and could not get system hostname:", err)
			}
		}
		hostnames = []string{*hostname}
	} else {
		var err error
		hostnames, err = resolveHostnames()
		if err != nil {
			log.Fatalln("Error while trying to resolve hostnames:", err)
		}
	}

	log.Debugln("Using hostnames", hostnames)

	// Query the DNS containers
	log.Debugln("Starting DNS query")

	// All configurations are always retrieved. If multiple configurations are found, we fail with an error.
	foundConfigs := make(map[string]map[string]string)

	// Query all found hostnames for DNS data
	for _, hostname := range hostnames {
		ourConfig := make(map[string]string, len(*configKeys))
		// Resolve all config entries for this hostname
		for _, name := range *configKeys {
			var queryName string
			if *prefix != "" {
				queryName = strings.Join([]string{name, *prefix}, ".")
			} else {
				queryName = name
			}
			value, found := resolveConfig(queryName, hostname, *requiredSuffix)
			if found {
				ourConfig[name] = value
			}
		}
		// Only add if we actually found some content.
		if len(ourConfig) > 0 {
			foundConfigs[hostname] = ourConfig
		}
	}

	resultConfig := make(map[string]string, len(*configKeys))
	if len(foundConfigs) == 1 || *allowMerge {
		// Try and merge non-conflicting results
		for _, config := range foundConfigs {
			for key, value := range config {
				if _, exists := resultConfig[key]; !exists {
					resultConfig[key] = value
				} else {
					log.Fatalln("Conflicting keys found for different domain trees:", foundConfigs)
				}
			}
		}
	} else if len(foundConfigs) > 1 {
		log.Fatalln("Found multiple configurations for different domain trees:", foundConfigs)
	}

	// Check that all requested keys were found. This is normally fatal, but
	// can be disabled.
	missingKeys := []string{}
	for _, name := range *configKeys {
		_, found := resultConfig[name]
		if !found {
			missingKeys = append(missingKeys, name)
		}
	}

	if len(missingKeys) > 0 {
		if *shouldFail {
			log.Fatalln("Missing requested keys:", missingKeys)
		} else {
			log.Debugln("Missing requested keys:", missingKeys)
		}
	}

	// Do output processing.
	switch *output {
	case OutputSimple:
		// Print out the found keys in the order they were requested, with blank lines for missing keys.
		for _, name := range *configKeys {
			value, _ := resultConfig[name]
			fmt.Println(value)
		}
	case OutputOneline:
		// Print out the found keys in the order they were requested, with empty strings for missing keys.
		var outputEntries []string
		for _, name := range *configKeys {
			value, _ := resultConfig[name]
			outputEntries = append(outputEntries, fmt.Sprintf("'%s'", value))
		}
		fmt.Println(strings.Join(outputEntries, " "))
	case OutputEnv:
		// Print out the found keys in the order they were requested suitable for eval'ing as shell script data
		for _, name := range *configKeys {
			value, _ := resultConfig[name]
			fmt.Printf("%s=\"%s\"\n", name, value)
		}
	case OutputJson:
		// Output the keys as a JSON object. This is suitable for many things, specifically p2cli input
		jsonBytes, err := json.Marshal(resultConfig)
		if err != nil {
			log.Fatalln("Error marshalling JSON:", err)
		}
		if _, err := os.Stdout.Write(jsonBytes); err != nil {
			log.Fatalln("Error writing to stdout.")
		}
	case OutputJsonPretty:
		jsonBytes, err := json.MarshalIndent(resultConfig, "", "  ")
		if err != nil {
			log.Fatalln("Error marshalling JSON:", err)
		}
		if _, err := os.Stdout.Write(jsonBytes); err != nil {
			log.Fatalln("Error writing to stdout:", err)
		}
	default:
		log.Fatalln("Invalid output format specified.")
	}

	log.Debugln("Exiting successfully.")
	os.Exit(0)
}

// Reverse resolve hostnames of the current host based on assigned IP addresses
func resolveHostnames() ([]string, error) {
	ipAddrs := []string{}

	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}, err
	}

	for _, netif := range ifaces {
		addrs, err := netif.Addrs()
		if err != nil {
			log.With("interface", netif.Name).Debugln("Skipping interface:", err)
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ipAddrs = append(ipAddrs, ip.String())
		}
	}

	// Reverse resolve all IPs, only keep those which match to a hostname
	hostnames := []string{}
	for _, ip := range ipAddrs {
		names, err := net.LookupAddr(ip)
		if err != nil {
			log.With("ip", ip).Debugln("Skipping IP - no result:", err)
			continue
		}
		hostnames = append(hostnames, names...)
	}

	return hostnames, nil
}

// Queries down the chain of possible hostnames and returns the config key
// found associated with a record.
// Multiple entries are concatenated without spaces and returned as a single string.
// Returns the value if any, and boolean indicating if the value was set blank
// or was not found.
func resolveConfig(name string, hostname string, requiredSuffix string) (string, bool) {
	log := log.With("name", name).With("hostname", hostname)

	// Split the hostname up into fragments
	hostParts := strings.Split(hostname, ".")

	for idx, _ := range hostParts {
		// Calculate the fragment
		domain := strings.Join(hostParts[idx:], ".")
		if !strings.HasSuffix(domain, requiredSuffix) {
			log.Debugln("Skipping", domain, "does not have required suffix", requiredSuffix)
		}

		// Determine the full DNS name with the config prefix
		dnsName := name + "." + domain

		txt, err := net.LookupTXT(dnsName)
		if err != nil {
			log.Debugln("Failed querying", dnsName, err)
		} else {
			log.Debugln("Lookup", dnsName, "found value", txt)
			return strings.Join(txt, ""), true
		}
	}

	log.Debugln("Found no keys")
	return "", false
}