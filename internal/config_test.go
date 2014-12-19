package domainstats

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dead10ck/goinvestigate"
)

var (
	inv    *goinvestigate.Investigate
	config *Config
)

func init() {
	home := os.Getenv("HOME")
	var err error
	config, err = NewConfig(filepath.Join(home, ".domainstats/default.toml"))
	if err != nil {
		log.Fatal(err)
	}
	inv = goinvestigate.New(config.APIKey)
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func strSliceEq(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAny(t *testing.T) {
	t.Parallel()
	type testStruct struct {
		field1 bool
		field2 bool
		field3 bool
	}
	validate := func(ts testStruct, expected bool) {
		if v := any(ts); v != expected {
			t.Fatalf("any(ts) should return %v", expected)
		}
	}

	ts := testStruct{true, true, true}
	validate(ts, true)
	ts = testStruct{false, true, true}
	validate(ts, true)
	ts = testStruct{false, false, true}
	validate(ts, true)
	ts = testStruct{false, false, false}
	validate(ts, false)
}

func TestDeriveHeader(t *testing.T) {
	t.Parallel()
	testHeader := config.DeriveHeader()
	refHeader := []string{
		"Domain", "Status", "SecurityCategories", "ContentCategories",
		"Cooccurrences", "RelatedDomains", "DGAScore", "Perplexity", "Entropy",
		"SecureRank2", "PageRank", "ASNScore", "PrefixScore", "RIPScore",
		"Popularity", "Fastflux", "Geodiversity", "GeodiversityNormalized",
		"TLDGeodiversity", "Geoscore", "KSTest", "Attack", "ThreatType",
		"TaggingDates", "RR Periods", "Age", "TTLsMin", "TTLsMax", "TTLsMean",
		"TTLsMedian", "TTLsStdDev", "CountryCodes", "ASNs", "Prefixes", "RIPSCount",
		"RIPSDiversity", "Locations", "GeoDistanceSum", "GeoDistanceMean",
		"NonRoutable", "MailExchanger", "CName", "FFCandidate", "RIPSStability",
		"BaseDomain", "IsSubdomain",
	}
	verifyHeader := func() {
		if len(testHeader) != len(refHeader) {
			t.Fatalf("testHeader = %v, but should = %v", testHeader, refHeader)
		}
		for i := range testHeader {
			if testHeader[i] != refHeader[i] {
				t.Fatalf("testHeader = %v, but should = %v", testHeader, refHeader)
			}
		}
	}
	verifyHeader()

	varConfig := Config{
		Status:     true,
		Categories: CategoriesConfig{SecurityCategories: true},
		Security:   SecurityConfig{DGAScore: true},
	}

	refHeader = []string{
		"Domain", "Status", "SecurityCategories", "DGAScore",
	}
	testHeader = varConfig.DeriveHeader()
	verifyHeader()
}

func TestDeriveMessages(t *testing.T) {
	t.Parallel()
	msgs := config.DeriveMessages(inv, "www.google.com")

	if len(msgs) != 6 {
		t.Fatalf("msgs wrong length. Should be 6: %v\n", msgs)
	}

	i := 0
	_ = msgs[i].Q.(*CategorizationQuery)
	i++
	_ = msgs[i].Q.(*CooccurrencesQuery)
	i++
	_ = msgs[i].Q.(*RelatedQuery)
	i++
	_ = msgs[i].Q.(*SecurityQuery)
	i++
	_ = msgs[i].Q.(*DomainTagsQuery)
	i++
	_ = msgs[i].Q.(*DomainRRHistoryQuery)

	// take some out
	varConfig := Config{
		Status:     true,
		Categories: CategoriesConfig{SecurityCategories: true},
		Security:   SecurityConfig{DGAScore: true},
	}
	msgs = varConfig.DeriveMessages(inv, "www.google.com")

	i = 0
	_ = msgs[i].Q.(*CategorizationQuery)
	i++
	_ = msgs[i].Q.(*SecurityQuery)
}
