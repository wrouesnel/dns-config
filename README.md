[![Build Status](https://travis-ci.org/wrouesnel/dns-config.svg?branch=master)](https://travis-ci.org/wrouesnel/dns-config)
[![Coverage Status](https://coveralls.io/repos/github/wrouesnel/dns-config/badge.svg)](https://coveralls.io/github/wrouesnel/dns-config)
[![Go Report Card](https://goreportcard.com/badge/github.com/wrouesnel/dns-config)](https://goreportcard.com/report/github.com/wrouesnel/dns-config)

# DNS Config

General purpose tool for outputting or writing configuration files from DNS
TXT or SRV entries. 

It's goal is to allow a server image to be configured
entirely from DNS data which you would have to run and create anyway in 
order for its network services to work.

## Usage
`dns-config` assumes that the local hostname is not reliable by default. When
run it will automatically discover the local IP addresses and attempt to
reverse resolve them all against the default DNS server.

Valid hostnames are then queried recursively until a TXT record is found which
includes the given configuration key. SRV records are also supported.

Example:
```
host.example.com $ dns-config key
value
```
Returns a TXT record found under the following domains by priority:
```
key.host.example.com
key.example.com
key.com
```

The depth of the search can be limited by use of command `--required-suffix` 
commandline option e.g. `dns-config --required-suffix example.com` would 
limit the search to go no further then `key.example.com`.

Multiple output formats are supported. The most powerful is `json` which 
allows key queries to fed directly into a templating engine for writing 
more sophisticated config file formats.

## Flags in Detail
* `--log-level`
  Sets the logging level of the application. The only meaninful output
  will be produced at `debug` unless an error occurs.

### Output Flags
The apply to all modes of operation although hostname and ip modes make
some deliberate opinions in how they want to consider the flags.

* `--output-format`
  Set the format of the output. The following formats are supported:
  * `simple` - the default. Lists the values found 1 per line, in the
    order they were requested. 
  
  * `flags` - outputs the values as `--key=value` formatted space
    separated flags. This method is a convenience for daemons like Mesos
    which use this style.
  
  * `one-line` - outputs the values as a single line of string literals
    space separated. This format is suitable for being escaped into a
    shell array and then parsed with knowledge of key ordering in a loop
    e.g. 
    ```
    MYARRAY=( $(dns-config --output-format one-line get key1 key2 key3) )
    ```
  * `env` - outputs all values as key=value pairs suitable for being
    shell sourced as environment variables. Not guaranteed to produce
    valid shell script if your keys are not valid (i.e. get-ips will
    produce output like `192.168.0.1=somehostname` which doesn't parse).
    
    This is ideal for generating environment variable files for systemd.
    
  * `json` - outputs all keys and values as a line-delimited JSON object.
    This mode is intended when the data might be fed into another
    templating engine like the [`j2`](https://pypi.python.org/pypi/j2/1.2.1) 
    or [`p2`](https://github.com/wrouesnel/p2cli)
    
  * `json-pretty` - the same as JSON but pretty-prints the output.
  
* `--output` - specify the output file. The file is overwritten by
  default. The default output is stdout.
  
* `--append` - instead of overwriting, appends the results to the given
  file. This is most useful with `env` formatting to combine static and
  dynamic values for a systemd unit file.
  
* `--no-overwrite` - quietly exits with success if the given file already 
  exists. This provides "run-once" behavior with persistent storage, or 
  optional dynamism (i.e. if a configuration volume is mounted with 
  those files, the statically defined values can be used instead of DNS).
  
* `--output-only-if-empty` - quietly exits with success if the output
  file path exists but is of 0 bytes in size. Useful for filling out
  files which start out existing but blank if in need of configuration.
  
* `--entry-joiner` - when a key returns multiple values, join them
  together with this joining character. Defaults to a newline. How this
  is used depends on how you choose to format your DNS configurations.
  
* `--add-value-prefix` - string prefix to add to each value

* `--add-value-suffix` - string suffix to add to each value
  
### Lookup Options
* `--hostname` - can set the hostname use to do the lookup rather then
  discovering it. Defaults to the current hostname returned by
  os.Hostname()
* `--use-hostname` - when specified indicates to use the hostname
  specified by `--hostname`
  
### Commands
* `get` - The normally intended lookup mode of this tool. Takes a list
  of arguments which are key names to lookup as DNS prefixes to the
  discovered or provided hostnames. 
  * `--record-type` - DNS record type to search for. Defaults to `txt`
    for TXT records. Supports TXT and SRV (`srv`).

  * `--srv-no-port` - When looking up SRV records, suppress returning the
    port with the lookup.

  * `--srv-suppress-dot` - When looking up SRV records, suppress the trailing
    dot of the returned name (i.e. `host.example.com.` becomes the more
    common `host.example.com`.

  * `--reverse-lookup` - Attempt to reverse lookup results to IP addresses.
    This is extremely useful with hostname filtering for getting the intended
    bind IP of a service for a host. Hosts which fail to lookup are dropped.
    Values which look like host:port have the port element preserved (e.g.
    SRV lookup results).
    
  * `--filter-values-by-hostname` - Filter the value results of the query by
    the known hostnames of this host. This is useful when querying SRV
    records to discover port numbers, but it is a string-based filter
    and will work for any type of return values. Accepts the options:
    * `none` - don't filter
    * `ours` - return only results which contain one of our hostnames
    * `theirs` - return only results do NOT contain one of our hostnames

  * `--name-suffix` - a suffix to the list of names which should be
    queried for but not looked for in arguments. 
    e.g. `--suffix config key1` results in dns queries for for 
    `key1.config` but the returned key name will still be `key1`.
  
  * `--no-fail` - if a key can't be retreived, do _not_ exit with 
    failure (status 1).
    
  * `--fail-if-empty` - if a key is found but is blank, exit with
    failure. This is useful when using hostname filtering to determine
    membership of a SRV recordset, for example.

  * `--suppress-blank` - if a key is found but is the empty string, suppress
    emitting it as a key-value entirely. This is useful when building formatted
    constructs with the prefix/postfix options.
  
  * `--hostname-only` - prevents querying down the name hierarchy for
    values i.e. if looking for `key1` only `key1.host.example.com` will
    be queried, not `key1.example.com` and `key1.com` as well.
  
  * `--allow-merge` - allow unrelated hierarchies with matching keys to
    to be merged. For example if a host has 2 DNS names on different IPs
    e.g. `host.blue.com` and `host.green.com`, then a query for `key1`
    and `key2` would normally disallow the clash of `key1.host.blue.com` 
    and `key1.green.com` both returning (possibly unrelated) data.
    `--allow-merge` will instead allow `key1` and `key2` to be combined
    from the 2 hierarchies.
    
  * `--additive` - normally a more specific key overrides a less specific
  key. `--additive` indicates that all values of a key should be combined
  and returned. So `key1.host.example.com` and `key1.example.com` both
  exist, their values will be combined (as determined by `--entry-joiner`)

* `get-ips` - Print the list of discovered IPs which have hostnames for
  this host. The returned data is output as host=ip, so output 
  formatting which prints key-values will print the first hostname 
  which matched that IP.

* `get-hostnames` - Print the list of hostnames discovered for this
  machine. The returned data is output as ip=host, so output formatting
  which prints the key-values will print the IP and then a list of
  hostnames which match it.

## More Help

See the `examples` folder for a dockerfile and dnsmasq configuration which
demonstrates some of the uses.
