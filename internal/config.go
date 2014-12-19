package domainstats

import (
	"log"
	"os"
	"path"
	"reflect"

	"github.com/BurntSushi/toml"
	"github.com/dead10ck/goinvestigate"
)

var (
	DefaultConfigPath string
)

func init() {
	home := os.Getenv("HOME")
	if home == "" {
		log.Fatal("HOME environment variable not set. Wrong platform?")
	}

	DefaultConfigPath = path.Join(home, "/.domainstats/default.toml")
}

// Takes a struct that consists of just bool fields
// and returns true if any of the fields are true
func any(structField interface{}) bool {
	rType := reflect.TypeOf(structField)
	rInterfaceVal := reflect.ValueOf(structField)
	rVal := rInterfaceVal.Convert(rType)
	for i := 0; i < rVal.NumField(); i++ {
		if rVal.Field(i).Bool() {
			return true
		}
	}
	return false
}

// Derive the header of the CSV output file from the config
func (c *Config) DeriveHeader() (header []string) {
	appendField := func(field string, cond bool) {
		if cond {
			header = append(header, field)
		}
	}

	appendFields := func(structField interface{}) {
		rType := reflect.TypeOf(structField)
		rInterfaceVal := reflect.ValueOf(structField)
		rVal := rInterfaceVal.Convert(rType)
		for i := 0; i < rVal.NumField(); i++ {
			fieldVal := rVal.Type().Field(i)
			fieldName := fieldVal.Name
			if fieldName != "Labels" {
				appendField(fieldName, rVal.Field(i).Bool())
			}
		}
	}

	// add the domain to the front
	header = append(header, "Domain")

	// add the fields in the same order the queries are constructed
	appendField("Status", c.Status)
	appendFields(c.Categories)
	if any(c.Cooccurrences) {
		appendField("Cooccurrences", true)
	}
	if any(c.Related) {
		appendField("RelatedDomains", true)
	}
	appendFields(c.Security)
	if any(c.TaggingDates) {
		appendField("TaggingDates", true)
	}
	if any(c.DomainRRHistory.Periods) {
		appendField("RR Periods", true)
	}
	appendFields(c.DomainRRHistory.Features)

	return header
}

// returns the list of Investigate functions to call for each domain
func (c *Config) DeriveMessages(inv *goinvestigate.Investigate,
	domain string) (msgs []*DomainQueryMessage) {
	if any(c.Categories) || c.Status {
		msgs = append(msgs, &DomainQueryMessage{
			&CategorizationQuery{
				DomainQuery{inv, domain},
				c.Categories.Labels,
			},
			make(chan DomainQueryResponse, 1),
		})
	}
	if any(c.Cooccurrences) {
		msgs = append(msgs, &DomainQueryMessage{
			&CooccurrencesQuery{
				DomainQuery{inv, domain},
			},
			make(chan DomainQueryResponse, 1),
		})
	}
	if any(c.Related) {
		msgs = append(msgs, &DomainQueryMessage{
			&RelatedQuery{
				DomainQuery{inv, domain},
			},
			make(chan DomainQueryResponse, 1),
		})
	}
	if any(c.Security) {
		msgs = append(msgs, &DomainQueryMessage{
			&SecurityQuery{
				DomainQuery{inv, domain},
			},
			make(chan DomainQueryResponse, 1),
		})
	}
	if any(c.TaggingDates) {
		msgs = append(msgs, &DomainQueryMessage{
			&DomainTagsQuery{
				DomainQuery{inv, domain},
			},
			make(chan DomainQueryResponse, 1),
		})
	}
	if any(c.DomainRRHistory.Periods) || any(c.DomainRRHistory.Features) {
		msgs = append(msgs, &DomainQueryMessage{
			&DomainRRHistoryQuery{
				DomainQuery{inv, domain},
				"A",
			},
			make(chan DomainQueryResponse, 1),
		})
	}
	return msgs
}

// Returns a new Config object. Reads the TOML file given by configFilePath.
func NewConfig(configFilePath string) (config *Config, err error) {
	if _, err := toml.DecodeFile(configFilePath, &config); err != nil {
		log.Fatal(err)
	}

	if config.APIKey == "" {
		log.Fatal("Config file is missing APIKey")
	}

	return config, nil
}

// Generates a default config and writes it to ~/.domainstats/default.toml
func GenerateDefaultConfig(apiKey string) error {
	configDir := path.Dir(DefaultConfigPath)

	err := os.MkdirAll(configDir, 0700)

	if err != nil {
		return err
	}

	configFile, err := os.Create(DefaultConfigPath)
	if err != nil {
		return err
	}

	trueConfig := Config{
		APIKey: apiKey,
		Status: true,
		Categories: CategoriesConfig{
			Labels:             true,
			SecurityCategories: true,
			ContentCategories:  true,
		},
		Cooccurrences: DomainScoreConfig{
			Domain: true,
			Score:  true,
		},
		Related: DomainScoreConfig{
			Domain: true,
			Score:  true,
		},
		Security: SecurityConfig{
			DGAScore:               true,
			Perplexity:             true,
			Entropy:                true,
			SecureRank2:            true,
			PageRank:               true,
			ASNScore:               true,
			PrefixScore:            true,
			RIPScore:               true,
			Popularity:             true,
			Fastflux:               true,
			Geodiversity:           true,
			GeodiversityNormalized: true,
			TLDGeodiversity:        true,
			Geoscore:               true,
			KSTest:                 true,
			Attack:                 true,
			ThreatType:             true,
		},
		TaggingDates: TaggingDatesConfig{
			Begin:    true,
			End:      true,
			Category: true,
			Url:      true,
		},
		DomainRRHistory: DomainRRHistoryConfig{
			Periods: DomainRRHistoryPeriodConfig{
				FirstSeen: true,
				LastSeen:  true,
				Name:      true,
				TTL:       true,
				Class:     true,
				Type:      true,
				RR:        true,
			},
			Features: DomainRRHistoryFeaturesConfig{
				Age:             true,
				TTLsMin:         true,
				TTLsMax:         true,
				TTLsMean:        true,
				TTLsMedian:      true,
				TTLsStdDev:      true,
				CountryCodes:    true,
				ASNs:            true,
				Prefixes:        true,
				RIPSCount:       true,
				RIPSDiversity:   true,
				Locations:       true,
				GeoDistanceSum:  true,
				GeoDistanceMean: true,
				NonRoutable:     true,
				MailExchanger:   true,
				CName:           true,
				FFCandidate:     true,
				RIPSStability:   true,
				BaseDomain:      true,
				IsSubdomain:     true,
			},
		},
	}

	tomlEncoder := toml.NewEncoder(configFile)
	err = tomlEncoder.Encode(trueConfig)
	if err != nil {
		return err
	}

	return nil
}

type Config struct {
	APIKey          string
	Status          bool
	Categories      CategoriesConfig
	Cooccurrences   DomainScoreConfig
	Related         DomainScoreConfig
	Security        SecurityConfig
	TaggingDates    TaggingDatesConfig
	DomainRRHistory DomainRRHistoryConfig
}

type CategoriesConfig struct {
	Labels             bool
	SecurityCategories bool
	ContentCategories  bool
}

type DomainScoreConfig struct {
	Domain bool
	Score  bool
}

type SecurityConfig struct {
	DGAScore               bool
	Perplexity             bool
	Entropy                bool
	SecureRank2            bool
	PageRank               bool
	ASNScore               bool
	PrefixScore            bool
	RIPScore               bool
	Popularity             bool
	Fastflux               bool
	Geodiversity           bool
	GeodiversityNormalized bool
	TLDGeodiversity        bool
	Geoscore               bool
	KSTest                 bool
	Attack                 bool
	ThreatType             bool
}

type TaggingDatesConfig struct {
	Begin    bool
	End      bool
	Category bool
	Url      bool
}

type DomainRRHistoryConfig struct {
	Periods  DomainRRHistoryPeriodConfig
	Features DomainRRHistoryFeaturesConfig
}

type DomainRRHistoryPeriodConfig struct {
	FirstSeen bool
	LastSeen  bool
	Name      bool
	TTL       bool
	Class     bool
	Type      bool
	RR        bool
}

type DomainRRHistoryFeaturesConfig struct {
	Age             bool
	TTLsMin         bool
	TTLsMax         bool
	TTLsMean        bool
	TTLsMedian      bool
	TTLsStdDev      bool
	CountryCodes    bool
	ASNs            bool
	Prefixes        bool
	RIPSCount       bool
	RIPSDiversity   bool
	Locations       bool
	GeoDistanceSum  bool
	GeoDistanceMean bool
	NonRoutable     bool
	MailExchanger   bool
	CName           bool
	FFCandidate     bool
	RIPSStability   bool
	BaseDomain      bool
	IsSubdomain     bool
}
