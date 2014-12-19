[![Build Status](https://travis-ci.org/dead10ck/domainstats.svg?branch=master)](https://travis-ci.org/dead10ck/domainstats)
# domainstats
`domainstats` is a tool to query the
[OpenDNS Investigate](https://sgraph.opendns.com/main) API using a list of domains,
outputting the results to a flat Tab-Separated Value (TSV) file.
It is fully configurable with a [TOML](https://github.com/toml-lang/toml) file;
anything and everything that one can query the Investigate API for can be fetched
and written out to a flat TSV file. It also takes full advantage of Go's 
concurrency mechanisms, so requests are paralellized.

## Install & Setup
To install, simply download the correct binary from the Releases page.

Once you have it installed, generate a default config file:

```sh
$ ./domainstats -setup <Your API Key>
Config file generated in ~/.domainstats/default.toml
```

where you should replace `<Your API Key>` with your
[Investigate API key](https://sgraph.opendns.com/tokens-view).

### Build from source
To build from the source, first, make sure your
[`$GOPATH`](http://golang.org/doc/code.html#GOPATH) is set.

This project uses [Godep](https://github.com/tools/godep) to manage dependencies.
If you don't already have it installed, `go get` it:

```sh
$ go get github.com/tools/godep
```

Then, you can download and build/install `domainstats` with:

```sh
$ go get -d github.com/dead10ck/domainstats
$ cd $GOPATH/src/github.com/dead10ck/domainstats
$ godep go install
```

## TOML Configuration
The default config file has all options set to true.

```toml
APIKey = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
Status = true

[Categories]
  Labels = true
  SecurityCategories = true
  ContentCategories = true

[Cooccurrences]
  Domain = true
  Score = true

[Related]
  Domain = true
  Score = true

[Security]
  DGAScore = true
  Perplexity = true
  Entropy = true
  SecureRank2 = true
  PageRank = true
  ASNScore = true
  PrefixScore = true
  RIPScore = true
  Popularity = true
  Fastflux = true
  Geodiversity = true
  GeodiversityNormalized = true
  TLDGeodiversity = true
  Geoscore = true
  KSTest = true
  Attack = true
  ThreatType = true

[TaggingDates]
  Begin = true
  End = true
  Category = true
  Url = true

[DomainRRHistory]
  [DomainRRHistory.Periods]
    FirstSeen = true
    LastSeen = true
    Name = true
    TTL = true
    Class = true
    Type = true
    RR = true
  [DomainRRHistory.Features]
    Age = true
    TTLsMin = true
    TTLsMax = true
    TTLsMean = true
    TTLsMedian = true
    TTLsStdDev = true
    CountryCodes = true
    ASNs = true
    Prefixes = true
    RIPSCount = true
    RIPSDiversity = true
    Locations = true
    GeoDistanceSum = true
    GeoDistanceMean = true
    NonRoutable = true
    MailExchanger = true
    CName = true
    FFCandidate = true
    RIPSStability = true
```

Each top-level table corresponds to a single endpoint of the Investigate API. The
more endpoints you make it query, the longer it will take to complete the queries.
You'll likely want to turn some of the flags off. To do so, you can either change
the values to `false`, or delete the line entirely.

I recommend you copy the default config file, instead of editing it directly.

```sh
$ cp ~/.domainstats/default.toml ~/.domainstats/myconfig.toml
```

If you only want, e.g., status, cooccurrences, RIP scores, and threat type, you can use
a config file like so:

```toml
APIKey = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
Status = true

[Cooccurrences]
  Domain = true
  Score = true

[Security]
  RIPScore = true
  ThreatType = true
```

## Usage

`domainstats` takes a file that contains a list of domains; e.g., say you have a
file named `bad_domains.txt`:

```
0.i.offerscdn.net
0.r.msn.com
0.talkgadget.google.com
0.hiexistence.com
0.kicksonfire.net
0.umps3-c1-was.salesforce.com
0.client-channel.google.com
0.everyday-families.com
0.thethriftynetwork.com
0.s3.envato.com
```

You can query these domains like so:

```sh
$ ./domainstats -c ~/.domainstats/myconfig.toml -out domains.tsv bad_domains.txt
```

This will output a TSV file with all the requested information in a file named
`domains.tsv`, which you can then import in a spreadsheet application, or open with
a simple text editor.

Without the `-c` option to specify a config, it uses the default config
(i.e., it queries and outputs everything):

```sh
$ ./domainstats -out domains.tsv bad_domains.txt
```
