[![Build Status](https://travis-ci.org/wrouesnel/dns-config.svg?branch=master)](https://travis-ci.org/wrouesnel/dns-config)

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


## More Help

See the `examples` folder for a dockerfile and dnsmasq configuration which
demonstrates some of the uses.
