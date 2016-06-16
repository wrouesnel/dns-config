/*
	This utility retrieves configuration information from DNS TXT records by reverse
	resolving host IPs.
 */

package main

import (
	"net"
	"os"
	"strings"
	"io"
	"flag"
	"fmt"
	"encoding/json"

	"gopkg.in/alecthomas/kingpin.v2"
	"github.com/wrouesnel/go.log"
)

const (
	OutputSimple = "simple"
	OutputOneline = "one-line"
	OutputEnv = "env"
	OutputJson = "json"
	OutputJsonPretty = "json-pretty"

	DnsTypeTXT = "txt"
	DnsTypeSRV = "srv"
)

var Version = "0.0.0-dev"

var (
	app = kingpin.New("dns-config", "general purpose configuration from DNS tool")

	logLevel = app.Flag("log-level", "Logging level").Default("info").String()

	useHostname = app.Flag("use-hostname", "Use a specified hostname, rather then reverse resolving IPs.").Bool()
	hostname = app.Flag("hostname", "Hostname to query as if --use-hostname. Defaults to system hostname.").String()

	recordType = app.Flag("record-type", fmt.Sprintf("DNS record type to search for (%s, %s)", DnsTypeSRV, DnsTypeTXT)).Default(DnsTypeTXT).Enum(DnsTypeSRV, DnsTypeTXT)

	suffix = app.Flag("name-suffix", "Standard prefix appended to all tags. The suffix is not added to the name in outputs.").String()
	requiredSuffix = app.Flag("required-suffix", "If set, require all resolved parameters to end with this suffix.").String()

	noFail = app.Flag("no-fail", "Don't fail if a requested flag can't be found.").Bool()
	allowMerge = app.Flag("allow-merge", "Allow non-conflicting configuration from multiple domain paths to be merged. This is usually a bad idea").Bool()
	hostnameOnly = app.Flag("hostname-only", "Do not recursively query the path hierarchy. Use the top-level hostname only. Overrides required-suffix.").Bool()
	additiveQuery = app.Flag("additive", "Provide configuration for names from all domain levels. This means keys with the same name have their values combined.").Bool()

	output = app.Flag("output-format", fmt.Sprintf("Set the output format (%s, %s, %s, %s, %s)", OutputSimple, OutputOneline, OutputEnv, OutputJson, OutputJsonPretty)).Default(OutputSimple).Enum(OutputSimple, OutputOneline, OutputEnv, OutputJson, OutputJsonPretty)
	outputPath = app.Flag("output", "File to write output to. Defaults to stdout.").Default("-").String()
	outputAppend = app.Flag("append", "Append rather then overwriting output file.").Bool()
	entryJoiner = app.Flag("entry-joiner", "String to use for joining multiple entries with the same name. Defaults to newline.").Default("\n").String()

	configKeys = app.Arg("name", "Key names (dns-prefixes) to search for configuration values. Returned in-order for \"simple\" output type.").Required().Strings()
)

func main() {
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.Version(Version)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	flag.Set("log.level", *logLevel)

	// Sanity check conflictable values
	if *requiredSuffix != "" && *hostnameOnly {
		log.Fatalln("--hostname-only overrides --required-suffix, meaning it will have no effect.")
	}

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
			if *suffix != "" {
				queryName = strings.Join([]string{name, *suffix}, ".")
			} else {
				queryName = name
			}

			// hostname-only is the same as setting required suffix to the exact
			// hostname we start querying at.
			if *hostnameOnly {
				*requiredSuffix = hostname
			}

			value, found := resolveConfig(*recordType, queryName, hostname, *requiredSuffix, *entryJoiner, *additiveQuery)
			if found {
				ourConfig[name] = value
			}
		}
		// Only add if we actually found some content.
		if len(ourConfig) > 0 {
			foundConfigs[hostname] = ourConfig
		}
	}

	// Process the results into a single final map
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
		if !*noFail {
			log.Fatalln("Missing requested keys:", missingKeys)
		} else {
			log.Debugln("Missing requested keys:", missingKeys)
		}
	}

	// Setup output file
	var outfd *os.File
	if *outputPath == "-" {
		outfd = os.Stdout
	} else {
		var err error
		flags := os.O_CREATE | os.O_WRONLY
		if *outputAppend {
			flags = flags | os.O_APPEND
		} else {
			flags = flags | os.O_TRUNC
		}
		outfd, err = os.OpenFile(*outputPath, flags, os.FileMode(0777))
		if err != nil {
			log.Fatalln("Could not open output file:", err)
		}
		defer outfd.Close()
	}

	// Write output
	writeOutput(*output, *configKeys, resultConfig, outfd)

	log.Debugln("Exiting successfully.")
	os.Exit(0)
}

// Process a map of key-values to an output writer
func writeOutput(outputType string, requestedKeys []string, resultMap map[string]string, wr io.Writer) {
	// Do output processing.
	switch *output {
	case OutputSimple:
		// Print out the found keys in the order they were requested, with blank lines for missing keys.
		for _, name := range requestedKeys {
			value, _ := resultMap[name]
			fmt.Fprintln(wr, value)
		}
	case OutputOneline:
		// Print out the found keys in the order they were requested, with empty strings for missing keys.
		var outputEntries []string
		for _, name := range requestedKeys {
			value, _ := resultMap[name]
			outputEntries = append(outputEntries, fmt.Sprintf("'%s'", value))
		}
		fmt.Fprintln(wr, strings.Join(outputEntries, " "))
	case OutputEnv:
		// Print out the found keys in the order they were requested suitable for eval'ing as shell script data
		for _, name := range requestedKeys {
			value, _ := resultMap[name]
			fmt.Fprintf(wr, "%s=\"%s\"\n", name, value)
		}
	case OutputJson:
		// Output the keys as a JSON object. This is suitable for many things, specifically p2cli input
		jsonBytes, err := json.Marshal(resultMap)
		if err != nil {
			log.Fatalln("Error marshalling JSON:", err)
		}
		if _, err := wr.Write(jsonBytes); err != nil {
			log.Fatalln("Error writing to stdout.")
		}
	case OutputJsonPretty:
		jsonBytes, err := json.MarshalIndent(resultMap, "", "  ")
		if err != nil {
			log.Fatalln("Error marshalling JSON:", err)
		}
		if _, err := wr.Write(jsonBytes); err != nil {
			log.Fatalln("Error writing to stdout:", err)
		}
	default:
		log.Fatalln("Invalid output format specified.")
	}
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
func resolveConfig(recordType string, name string, hostname string, requiredSuffix string, entryJoiner string, recurse bool) (string, bool) {
	log := log.With("name", name).With("hostname", hostname)

	// Split the hostname up into fragments
	hostParts := strings.Split(hostname, ".")

	results := []string{}

	for idx, _ := range hostParts {
		// Calculate the fragment
		domain := strings.Join(hostParts[idx:], ".")
		if !strings.HasSuffix(domain, requiredSuffix) {
			log.Debugln("Stopping iteration before", domain, " as it does not have required suffix", requiredSuffix)
			// Break now since we can't possibly continue
			break
		}
		// Determine the full DNS name with the config prefix
		dnsName := name + "." + domain

		result := []string{}
		var err error
		switch recordType {
		// TXT records are our conventional approach
		case DnsTypeTXT:
			result, err = net.LookupTXT(dnsName)
		// SRV records are unconventional - we infer their structure and treat
		// the result IPs as a list of joinable values.
		case DnsTypeSRV:
			var srvCname string
			var srvResults []*net.SRV
			srvCname, srvResults, err = net.LookupSRV("","",dnsName)
			log.Debugln("SRV lookup got CNAME", srvCname)
			// Construct a result array of <host>:<port> fragments.
			for _, srvResult := range srvResults {
				result = append(result, fmt.Sprintf("%s:%d", srvResult.Target, srvResult.Port))
			}
		default:
			log.Panicln("Unrecognized record type requested.")
		}

		if err != nil {
			log.Debugln("Failed querying", dnsName, err)
		} else {
			log.Debugln("Lookup", dnsName, "found value", result)
			results = append(results, result...)
			if !recurse {
				// If not recursing, terminate iteration
				break
			}
		}
	}

	if len(results) == 0 {
		log.Debugln("Found no keys")
		return "", false
	}
	return strings.Join(results, entryJoiner), true
}