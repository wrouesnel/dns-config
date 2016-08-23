/*
	This utility retrieves configuration information from DNS TXT records by reverse
	resolving host IPs.
*/

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/wrouesnel/go.log"
	"gopkg.in/alecthomas/kingpin.v2"
	"github.com/kballard/go-shellquote"
)

const (
	OutputSimple     = "simple"
	OutputAsFlags    = "flags"
	OutputOneline    = "one-line"
	OutputEnv        = "env"
	OutputJson       = "json"
	OutputJsonPretty = "json-pretty"

	DnsTypeTXT = "txt"
	DnsTypeSRV = "srv"

	HostnameFilterNone = "none"
	HostnameFilterOurs = "ours"
	HostnameFilterTheirs = "theirs"
)

var Version = "0.0.0-dev"

var (
	app = kingpin.New("dns-config", "general purpose configuration from DNS tool")

	logLevel = app.Flag("log-level", "Logging level").Default("info").String()

	// App-wide output configuration
	output            = app.Flag("output-format", fmt.Sprintf("Set the output format (%s, %s, %s, %s, %s, %s)", OutputSimple, OutputAsFlags, OutputOneline, OutputEnv, OutputJson, OutputJsonPretty)).Default(OutputSimple).Enum(OutputSimple, OutputAsFlags, OutputOneline, OutputEnv, OutputJson, OutputJsonPretty)
	outputPath        = app.Flag("output", "File to write output to. Defaults to stdout.").Default("-").String()
	outputAppend      = app.Flag("append", "Append rather then overwriting output file.").Bool()
	outputOverwrite = app.Flag("overwrite", "Overwrite the output file if it exists. If disabled, return success if file exists.").Default("true").Bool()
	outputOnlyIfEmpty = app.Flag("output-only-if-empty", "Only write output if the target file has a file size of 0").Bool()
	entryJoiner       = app.Flag("entry-joiner", "String to use for joining multiple entries with the same name. Defaults to newline.").Default("\n").String()
	outputPrefix	  = app.Flag("add-value-prefix", "String to prefix to every output value").String()
	outputSuffix	  = app.Flag("add-value-suffix", "String to suffix to every output value").String()

	requiredSuffix = app.Flag("required-suffix", "If set, require all resolved parameters to end with this suffix.").String()

	useHostname = app.Flag("use-hostname", "Use a specified hostname, rather then reverse resolving IPs.").Bool()
	hostname    = app.Flag("hostname", "Hostname to query as if --use-hostname. Defaults to system hostname.").String()

	getIPs       = app.Command("get-ips", "Print the list of discovered IPs for this host. Returns IPs can be limited with --required-suffix or --use-hostname.")
	getHostnames = app.Command("get-hostnames", "Get the hostnames available from DNS lookup for this host")

	get = app.Command("get", "Get a key value from DNS")

	recordType    = get.Flag("record-type", fmt.Sprintf("DNS record type to search for (%s, %s)", DnsTypeSRV, DnsTypeTXT)).Default(DnsTypeTXT).Enum(DnsTypeSRV, DnsTypeTXT)
	hostnameFilter = get.Flag("filter-values-by-hostname", fmt.Sprintf("Filter results by some critera (%s, %s, %s)", HostnameFilterNone, HostnameFilterOurs, HostnameFilterTheirs)).Default(HostnameFilterNone).Enum(HostnameFilterNone, HostnameFilterOurs, HostnameFilterTheirs)
	suffix        = get.Flag("name-suffix", "Standard prefix appended to all tags. The suffix is not added to the name in outputs.").String()
	hostnameOnly  = get.Flag("hostname-only", "Do not recursively query the path hierarchy. Use the top-level hostname only. Overrides required-suffix.").Bool()
	shouldFail    = get.Flag("fail", "Return failure if a requested flag cannot be found.").Default("true").Bool()
	shouldFailIfEmpty    = get.Flag("fail-if-empty", "Return failure if a requested flag is blank.").Default("true").Bool()
	allowMerge    = get.Flag("allow-merge", "Allow non-conflicting configuration from multiple domain paths to be merged. This is usually a bad idea").Bool()
	additiveQuery = get.Flag("additive", "Provide configuration for names from all domain levels. This means keys with the same name have their values combined.").Bool()

	configKeys = get.Arg("name", "Key names (dns-prefixes) to search for configuration values. Returned in-order for simple, one-line and env output types.").Required().Strings()
)

// An IP/Hostname pair
type IPHostnamesPair struct {
	Ip        net.IP
	Hostnames []string
}

type getWriterFunc func() (io.WriteCloser, error)

func main() {
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.Version(Version)
	parsedCmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	flag.Set("log.level", *logLevel)

	// Check no-overwrite flag. This is a trivial case which allows "only-once"
	// configuration, or aborting configuration and using already installed
	// values.
	{
		if *output != "-" {
			st, err := os.Stat(*output)
			if *outputOverwrite && !os.IsNotExist(err) {
				log.Debugln("Output file exists and no overwrite requested. Exiting with success.")
				os.Exit(0)
			}

			if err == nil {
				if st.Size() != 0 && !*outputOnlyIfEmpty {
					log.Debugln("Requested output only if the target file is empty and it is not.")
					os.Exit(0)
				}
			}
		}
	}


	var keys []string
	var resultConfig map[string]string
	var err error

	switch parsedCmd {
	case get.FullCommand():
		keys, resultConfig, err = cmdGet()
	case getHostnames.FullCommand():
		keys, resultConfig, err = cmdGetHostnames()
	case getIPs.FullCommand():
		keys, resultConfig, err = cmdGetIPs()
	}

	if err != nil {
		log.Errorln(err)
		os.Exit(1)
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
			log.Errorln("Could not open output file:", err)
			os.Exit(1)
		}
	}

	log.Debugln("Keys:", keys)
	log.Debugln("Result Map:", resultConfig)

	// Write output
	if err := writeOutput(*output, keys, resultConfig, outfd, *outputPrefix, *outputSuffix); err != nil {
		log.Errorln("Error writing output:", err)
		os.Exit(1)
	}
	outfd.Close()
	os.Exit(0)
}

// get-ips returns all the discovered IPs on the machine, optionally filtered
// by a required DNS suffix or hostname.
func cmdGetIPs() ([]string, map[string]string, error) {
	// Sanity check conflictable values
	if *useHostname && *requiredSuffix != "" {
		return []string{}, nil, errors.New("--use-hostname overrides --required-suffix, meaning it will have no effect.")
	}

	var suffix string
	if *useHostname {
		suffix = *hostname
	} else if *requiredSuffix != "" {
		suffix = *requiredSuffix
	}

	pairs, err := resolveIPsToHostnames()
	if err != nil {
		return []string{}, nil, errors.New(fmt.Sprintln("Error while resolving local IPs to hostnames:", err))
	}

	resultMap := make(map[string]string)
	matchedHostnames := []string{}
	for _, pair := range pairs {
		for _, hostname := range pair.Hostnames {
			if strings.HasSuffix(hostname, suffix) {
				resultMap[hostname] = pair.Ip.String()
				matchedHostnames = append(matchedHostnames, hostname)
				break // Found a match for this IP - break loop
			}
		}
	}

	return matchedHostnames, resultMap, nil
}

// get-hostnames returns all the discovered hostnames of a machine, optionally
// filtered by a required suffix.
func cmdGetHostnames() ([]string, map[string]string, error) {
	// Sanity check conflictable values
	if *useHostname && *requiredSuffix != "" {
		return []string{}, nil, errors.New("--use-hostname overrides --required-suffix, meaning it will have no effect.")
	}

	var suffix string
	if *useHostname {
		suffix = *hostname
	} else if *requiredSuffix != "" {
		suffix = *requiredSuffix
	}

	pairs, err := resolveIPsToHostnames()
	if err != nil {
		return []string{}, nil, errors.New(fmt.Sprintln("Error while resolving local IPs to hostnames:", err))
	}

	resultMap := make(map[string]string)
	matchedIPs := []string{}
	for _, pair := range pairs {
		for _, hostname := range pair.Hostnames {
			if strings.HasSuffix(hostname, suffix) {
				existingValue, ok := resultMap[pair.Ip.String()]
				if ok {
					resultMap[pair.Ip.String()] = strings.Join([]string{existingValue, hostname}, *entryJoiner)
				} else {
					resultMap[pair.Ip.String()] = hostname
					matchedIPs = append(matchedIPs, pair.Ip.String())
				}
			}
		}
	}

	log.Debugln("Exiting successfully.")
	return matchedIPs, resultMap, nil
}

// Implement the normal get command
func cmdGet() ([]string, map[string]string, error) {
	// Sanity check conflictable values
	if *requiredSuffix != "" && *hostnameOnly {
		return []string{}, nil, errors.New("--hostname-only overrides --required-suffix, meaning it will have no effect.")
	}

	// If no hostname, get the OS hostname. If that fails, then we can't really
	// do anything.
	var hostnames []string
	if *useHostname {
		if *hostname == "" {
			var err error
			*hostname, err = os.Hostname()
			if err != nil {
				return []string{}, nil, errors.New(fmt.Sprintln("No hostname specified and could not get system hostname:", err))
			}
		}
		hostnames = []string{*hostname}
	} else {
		var err error
		hostnames, err = resolveHostnames()
		if err != nil {
			return []string{}, nil, errors.New(fmt.Sprintln("Error while trying to resolve hostnames:", err))
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

			values, found := resolveConfig(*recordType, queryName, hostname, *requiredSuffix, *additiveQuery)
			if found {
				filteredResult := []string{}
				switch *hostnameFilter {
				case HostnameFilterNone:
					filteredResult = values
				case HostnameFilterOurs:
					for _, value := range values {
						for _, hostname := range hostnames {
							if strings.Contains(value, hostname) {
								// Contains one of our hostnames, allow it through.
								filteredResult = append(filteredResult, value)
								break
							}
						}
					}
				case HostnameFilterTheirs:
					for _, value := range values {
						for _, hostname := range hostnames {
							if !strings.Contains(value, hostname) {
								// Does not contain one of our hostnames, allow
								// it through.
								filteredResult = append(filteredResult, value)
								break
							}
						}
					}
				default:
					return []string{}, nil, errors.New(fmt.Sprintln("Unknown hostname filter option:", *hostnameFilter))
				}

				ourConfig[name] = strings.Join(filteredResult, *entryJoiner)
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
					return []string{}, nil, errors.New(fmt.Sprintln("Conflicting keys found for different domain trees:", foundConfigs))
				}
			}
		}
	} else if len(foundConfigs) > 1 {
		return []string{}, nil, errors.New(fmt.Sprintln("Found multiple configurations for different domain trees:", foundConfigs))
	}

	// Check that all requested keys were found. This is normally fatal, but
	// can be disabled.
	missingKeys := []string{}
	blankKeys := []string{}
	for _, name := range *configKeys {
		value, found := resultConfig[name]
		if !found {
			missingKeys = append(missingKeys, name)
		} else if value == "" {
			blankKeys = append(blankKeys, name)
		}
	}

	if len(missingKeys) > 0 {
		if *shouldFail {
			return []string{}, nil, errors.New(fmt.Sprintln("Missing requested keys:", missingKeys))
		} else {
			log.Debugln("Missing requested keys:", missingKeys)
		}
	}

	if len(blankKeys) > 0 {
		if *shouldFailIfEmpty {
			return []string{}, nil, errors.New(fmt.Sprintln("Got blank requested keys and requested failure:", blankKeys))
		} else {
			log.Debugln("Blank requested keys:", missingKeys)
		}
	}

	return *configKeys, resultConfig, nil
}

// Process a map of key-values to an output writer
func writeOutput(outputType string, requestedKeys []string, resultMap map[string]string, wr io.Writer, prefix string, suffix string) error {
	processedMap := make(map[string]string, len(resultMap))
	for k, v := range resultMap {
		processedMap[k] = fmt.Sprintf("%s%s%s", prefix, v, suffix)
	}

	// Do output processing.
	switch *output {
	case OutputSimple:
		// Print out the found keys in the order they were requested,
		// with blank lines for missing keys.
		for _, name := range requestedKeys {
			value, _ := processedMap[name]
			fmt.Fprintln(wr, value)
		}
	case OutputAsFlags:
		// Print out the found keys in the order they were requested, formatted
		// as --key=value command line flags.
		for _, name := range requestedKeys {
			value, _ := processedMap[name]
			fmt.Fprintf(wr, "%s=%s ", name, value)
		}
	case OutputOneline:
		// Print out the found keys in the order they were requested,
		// with empty strings for missing keys.
		var outputEntries []string
		for _, name := range requestedKeys {
			value, _ := processedMap[name]
			outputEntries = append(outputEntries, value)
		}

		fmt.Fprintln(wr, shellquote.Join(outputEntries...))
	case OutputEnv:
		// Print out the found keys in the order they were requested suitable
		// for eval'ing as shell script data. We make some effort to do escaping
		// here so the trivial case will work with Docker's brain-dead env-file
		// parser.
		for _, name := range requestedKeys {
			value, _ := processedMap[name]
			fmt.Fprintf(wr, "%s=%s\n", name, shellquote.Join(value))
		}
	case OutputJson:
		// Output the keys as a JSON object. This is suitable for many things,
		// specifically p2cli input
		jsonBytes, err := json.Marshal(processedMap)
		if err != nil {
			log.Errorln("Error marshalling JSON:", err)
			return err
		}
		if _, err := wr.Write(jsonBytes); err != nil {
			log.Errorln("Error writing to stdout.")
			return err
		}
	case OutputJsonPretty:
		jsonBytes, err := json.MarshalIndent(processedMap, "", "  ")
		if err != nil {
			log.Errorln("Error marshalling JSON:", err)
			return err
		}
		if _, err := wr.Write(jsonBytes); err != nil {
			log.Errorln("Error writing to stdout:", err)
			return err
		}
	default:
		log.Errorln("Invalid output format specified.")
		return errors.New("Invalid output format specified.")
	}

	return nil
}

// Reverse resolve hostnames of the current host based on assigned IP addresses
// Returns a string array of all hostnames
func resolveHostnames() ([]string, error) {
	pairs, err := resolveIPsToHostnames()
	if err != nil {
		return []string{}, err
	}
	hostnames := []string{}
	for _, pair := range pairs {
		hostnames = append(hostnames, pair.Hostnames...)
	}
	return hostnames, nil
}

// Reverse resolve hostnames of the current host based on assigned IP addresses.
// Returns an array of IP -> Hostname mappings.
func resolveIPsToHostnames() ([]IPHostnamesPair, error) {
	ipAddrs, err := getLocalIPAddresses()
	if err != nil {
		return []IPHostnamesPair{}, err
	}

	// Reverse resolve all IPs, only keep those which match to a hostname
	hostnamePairs := []IPHostnamesPair{}
	for _, ip := range ipAddrs {
		names, err := net.LookupAddr(ip.String())
		if err == nil {
			pair := IPHostnamesPair{
				Ip:        ip,
				Hostnames: names,
			}
			hostnamePairs = append(hostnamePairs, pair)
		} else {
			log.With("ip", ip.String()).Debugln("No DNS results for IP:", err)
		}
	}
	return hostnamePairs, nil
}

// Get a list of all the IP addresses on the system
func getLocalIPAddresses() ([]net.IP, error) {
	ipAddrs := []net.IP{}

	ifaces, err := net.Interfaces()
	if err != nil {
		return []net.IP{}, err
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
			ipAddrs = append(ipAddrs, ip)
		}
	}
	return ipAddrs, nil
}

// Queries down the chain of possible hostnames and returns the config key
// found associated with a record.
// Multiple entries are concatenated without spaces and returned as a single string.
// Returns the value if any, and boolean indicating if the value was set blank
// or was not found.
func resolveConfig(recordType string, name string, hostname string, requiredSuffix string, recurse bool) ([]string, bool) {
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
			srvCname, srvResults, err = net.LookupSRV("", "", dnsName)
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
		return []string{}, false
	}
	return results, true
}
