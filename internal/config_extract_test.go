package domainstats

import (
	"runtime"
	"testing"

	"github.com/dead10ck/goinvestigate"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func TestLocsToStr(t *testing.T) {
	t.Parallel()
	testLocs := []goinvestigate.Location{
		goinvestigate.Location{
			Lat: -100,
			Lon: 100,
		},
		goinvestigate.Location{
			Lat: -150,
			Lon: 150,
		},
		goinvestigate.Location{
			Lat: -200,
			Lon: 200,
		},
	}
	testLocsStr := locsToStr(testLocs)
	refStr := "-100:100, -150:150, -200:200"
	if testLocsStr != refStr {
		t.Fatalf("testLocsStr = %s, but should = %s", testLocsStr, refStr)
	}
}

func TestRrPeriodsToStr(t *testing.T) {
	t.Parallel()
	testRRPeriods := []goinvestigate.ResourceRecordPeriod{
		goinvestigate.ResourceRecordPeriod{
			FirstSeen: "2014-08-28",
			LastSeen:  "2014-08-29",
			RRs: []goinvestigate.ResourceRecord{
				goinvestigate.ResourceRecord{
					Name:  "TestRR1",
					TTL:   100,
					Class: "TestClass1",
					Type:  "TestType1",
					RR:    "TestRR1",
				},
				goinvestigate.ResourceRecord{
					Name:  "TestRR2",
					TTL:   200,
					Class: "TestClass2",
					Type:  "TestType2",
					RR:    "TestRR2",
				},
			},
		},
		goinvestigate.ResourceRecordPeriod{
			FirstSeen: "2014-07-28",
			LastSeen:  "2014-07-29",
			RRs: []goinvestigate.ResourceRecord{
				goinvestigate.ResourceRecord{
					Name:  "TestRR3",
					TTL:   300,
					Class: "TestClass3",
					Type:  "TestType3",
					RR:    "TestRR3",
				},
				goinvestigate.ResourceRecord{
					Name:  "TestRR4",
					TTL:   400,
					Class: "TestClass4",
					Type:  "TestType4",
					RR:    "TestRR4",
				},
			},
		},
	}
	refStr := "2014-08-28:2014-08-29:TestRR1:100:TestClass1:TestType1:TestRR1, " +
		"2014-08-28:2014-08-29:TestRR2:200:TestClass2:TestType2:TestRR2, " +
		"2014-07-28:2014-07-29:TestRR3:300:TestClass3:TestType3:TestRR3, " +
		"2014-07-28:2014-07-29:TestRR4:400:TestClass4:TestType4:TestRR4"

	testStr := config.rrPeriodsToStr(testRRPeriods)

	if refStr != testStr {
		t.Fatal("testStr = %s, but should = %s", testStr, refStr)
	}

	// sanity check for some config variation
	varConfig := Config{
		DomainRRHistory: DomainRRHistoryConfig{
			Periods: DomainRRHistoryPeriodConfig{
				FirstSeen: true,
				LastSeen:  true,
				RR:        true,
			},
		},
	}

	refStr = "2014-08-28:2014-08-29:TestRR1, " +
		"2014-08-28:2014-08-29:TestRR2, " +
		"2014-07-28:2014-07-29:TestRR3, " +
		"2014-07-28:2014-07-29:TestRR4"

	testStr = varConfig.rrPeriodsToStr(testRRPeriods)

	if refStr != testStr {
		t.Fatal("testStr = %s, but should = %s", testStr, refStr)
	}
}

func TestGeoString(t *testing.T) {
	t.Parallel()
	testGs := []goinvestigate.GeoFeatures{
		goinvestigate.GeoFeatures{
			CountryCode: "US",
			VisitRatio:  0.5,
		},
		goinvestigate.GeoFeatures{
			CountryCode: "UA",
			VisitRatio:  0.7,
		},
	}
	testStr := geoString(testGs)
	refStr := "US:0.5, UA:0.7"
	if testStr != refStr {
		t.Fatalf("testStr = %s, but should = %s", testStr, refStr)
	}
}

func TestAppendIf(t *testing.T) {
	t.Parallel()
	testStrSlice := []string{"foo"}
	testStrSliceAppended := appendIf(testStrSlice, "bar", true)
	testStrSliceNotAppended := appendIf(testStrSlice, "bar", false)

	if len(testStrSliceAppended) != 2 || testStrSliceAppended[1] != "bar" {
		t.Fatal("testStrSliceAppended should have \"bar\" in it")
	}
	if len(testStrSliceNotAppended) != 1 {
		t.Fatal("testStrSliceAppended should NOT have \"bar\" in it")
	}
}

func TestExtractDomainCatInfo(t *testing.T) {
	dc := &goinvestigate.DomainCategorization{
		Status:             1,
		SecurityCategories: []string{"Malware", "Botnet", "Trojan"},
		ContentCategories:  []string{"8", "15", "23"},
	}
	ref := []string{"1", "Malware, Botnet, Trojan", "8, 15, 23"}
	test, _ := config.ExtractCSVSubRow(dc)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// test with fields omitted
	config.Status = false
	ref = []string{"Malware, Botnet, Trojan", "8, 15, 23"}
	test, _ = config.ExtractCSVSubRow(dc)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Status = true

	config.Categories.SecurityCategories = false
	ref = []string{"1", "8, 15, 23"}
	test, _ = config.ExtractCSVSubRow(dc)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Categories.SecurityCategories = true

	// all off should return an empty slice
	config.Status = false
	config.Categories.SecurityCategories = false
	config.Categories.ContentCategories = false
	ref = []string{}
	test, _ = config.ExtractCSVSubRow(dc)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Status = true
	config.Categories.SecurityCategories = true
	config.Categories.ContentCategories = true

	// if a field is configured to be fetched, but it is just
	// empty, it should still return blank fields
	dcBlank := &goinvestigate.DomainCategorization{
		Status:             1,
		SecurityCategories: []string{},
		ContentCategories:  []string{},
	}
	ref = []string{"1", "", ""}
	test, _ = config.ExtractCSVSubRow(dcBlank)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
}

func TestExtractRelatedDomainInfo(t *testing.T) {
	rd := []goinvestigate.RelatedDomain{
		goinvestigate.RelatedDomain{
			Domain: "www.example1.com",
			Score:  10,
		},
		goinvestigate.RelatedDomain{
			Domain: "info.example2.com.com",
			Score:  9,
		},
		goinvestigate.RelatedDomain{
			Domain: "support.example.com",
			Score:  3,
		},
	}

	ref := []string{"www.example1.com:10, info.example2.com.com:9, support.example.com:3"}
	test, _ := config.ExtractCSVSubRow(rd)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// turn off scores
	config.Related.Score = false
	ref = []string{"www.example1.com, info.example2.com.com, support.example.com"}
	test, _ = config.ExtractCSVSubRow(rd)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Related.Score = true

	// turn off domains
	config.Related.Domain = false
	ref = []string{"10, 9, 3"}
	test, _ = config.ExtractCSVSubRow(rd)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Related.Domain = true

	// without either, should just return an empty slice
	config.Related.Domain = false
	config.Related.Score = false
	ref = []string{}
	test, _ = config.ExtractCSVSubRow(rd)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Related.Domain = true
	config.Related.Score = true

	// if a field is configured to be fetched, but it is just
	// empty, it should still return blank fields
	rdBlank := []goinvestigate.RelatedDomain{}
	ref = []string{""}
	test, _ = config.ExtractCSVSubRow(rdBlank)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
}

func TestExtractCooccurrenceInfo(t *testing.T) {
	cl := []goinvestigate.Cooccurrence{
		goinvestigate.Cooccurrence{
			Domain: "download.example.com",
			Score:  0.9320288065469468,
		},
		goinvestigate.Cooccurrence{
			Domain: "query.example.com",
			Score:  0.06797119345305325,
		},
	}

	ref := []string{"download.example.com:0.9320288065469468, query.example.com:0.06797119345305325"}
	test, _ := config.ExtractCSVSubRow(cl)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// turn off scores
	config.Cooccurrences.Score = false
	ref = []string{"download.example.com, query.example.com"}
	test, _ = config.ExtractCSVSubRow(cl)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Cooccurrences.Score = true

	// turn off domains
	config.Cooccurrences.Domain = false
	ref = []string{"0.9320288065469468, 0.06797119345305325"}
	test, _ = config.ExtractCSVSubRow(cl)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Cooccurrences.Domain = true

	// both false should return an empty slice
	config.Cooccurrences.Domain = false
	config.Cooccurrences.Score = false
	ref = []string{}
	test, _ = config.ExtractCSVSubRow(cl)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Cooccurrences.Domain = true
	config.Cooccurrences.Score = true

	// if a field is configured to be fetched, but it is just
	// empty, it should still return blank fields
	refBlank := []goinvestigate.Cooccurrence{}
	ref = []string{""}
	test, _ = config.ExtractCSVSubRow(refBlank)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
}

func TestExtractSecurityFeaturesInfo(t *testing.T) {
	sec := &goinvestigate.SecurityFeatures{
		DGAScore:    38.301771886101335,
		Perplexity:  0.4540313302593146,
		Entropy:     2.5216406363433186,
		SecureRank2: -1.3135141095601992,
		PageRank:    0.0262532,
		ASNScore:    -29.75810625887133,
		PrefixScore: -64.9070502788884,
		RIPScore:    -75.64720536038982,
		Popularity:  25.335450495507196,
		Fastflux:    false,
		Geodiversity: []goinvestigate.GeoFeatures{
			goinvestigate.GeoFeatures{CountryCode: "UA", VisitRatio: 0.24074075},
			goinvestigate.GeoFeatures{CountryCode: "IN", VisitRatio: 0.018518519},
		},
		GeodiversityNormalized: []goinvestigate.GeoFeatures{
			goinvestigate.GeoFeatures{CountryCode: "AP", VisitRatio: 0.3761535390278368},
			goinvestigate.GeoFeatures{CountryCode: "US", VisitRatio: 0.0005015965168831449},
		},
		TLDGeodiversity: []goinvestigate.GeoFeatures{
			goinvestigate.GeoFeatures{CountryCode: "ID", VisitRatio: 0.3848226710420966},
			goinvestigate.GeoFeatures{CountryCode: "BY", VisitRatio: 0.1127399438411313},
		},
		Geoscore:   0,
		KSTest:     0,
		Attack:     "DDoS",
		ThreatType: "Malware",
	}
	ref := []string{"38.301771886101335", "0.4540313302593146",
		"2.5216406363433186", "-1.3135141095601992", "0.0262532",
		"-29.75810625887133", "-64.9070502788884", "-75.64720536038982",
		"25.335450495507196", "false",
		"UA:0.24074075, IN:0.018518519",
		"AP:0.3761535390278368, US:0.0005015965168831449",
		"ID:0.3848226710420966, BY:0.1127399438411313",
		"0", "0", "DDoS", "Malware",
	}
	test, _ := config.ExtractCSVSubRow(sec)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// couple of sanity checks - turning off Perplexity and Entropy
	config.Security.Perplexity = false
	config.Security.Entropy = false
	ref = []string{"38.301771886101335", "-1.3135141095601992", "0.0262532",
		"-29.75810625887133", "-64.9070502788884", "-75.64720536038982",
		"25.335450495507196", "false",
		"UA:0.24074075, IN:0.018518519",
		"AP:0.3761535390278368, US:0.0005015965168831449",
		"ID:0.3848226710420966, BY:0.1127399438411313",
		"0", "0", "DDoS", "Malware",
	}
	test, _ = config.ExtractCSVSubRow(sec)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Security.Perplexity = true
	config.Security.Entropy = true

	// turn off GeodiversityNormalized and TLDGeodiversity
	config.Security.GeodiversityNormalized = false
	config.Security.TLDGeodiversity = false
	ref = []string{"38.301771886101335", "0.4540313302593146",
		"2.5216406363433186", "-1.3135141095601992", "0.0262532",
		"-29.75810625887133", "-64.9070502788884", "-75.64720536038982",
		"25.335450495507196", "false",
		"UA:0.24074075, IN:0.018518519",
		"0", "0", "DDoS", "Malware",
	}
	test, _ = config.ExtractCSVSubRow(sec)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Security.GeodiversityNormalized = true
	config.Security.TLDGeodiversity = true

	// turning off everyting should return an empty slice
	config.Security.DGAScore = false
	config.Security.Perplexity = false
	config.Security.Entropy = false
	config.Security.SecureRank2 = false
	config.Security.PageRank = false
	config.Security.ASNScore = false
	config.Security.PrefixScore = false
	config.Security.RIPScore = false
	config.Security.Fastflux = false
	config.Security.Popularity = false
	config.Security.Geodiversity = false
	config.Security.GeodiversityNormalized = false
	config.Security.TLDGeodiversity = false
	config.Security.Geoscore = false
	config.Security.KSTest = false
	config.Security.Attack = false
	config.Security.ThreatType = false
	ref = []string{}
	test, _ = config.ExtractCSVSubRow(sec)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Security.DGAScore = true
	config.Security.Perplexity = true
	config.Security.Entropy = true
	config.Security.SecureRank2 = true
	config.Security.PageRank = true
	config.Security.ASNScore = true
	config.Security.PrefixScore = true
	config.Security.RIPScore = true
	config.Security.Fastflux = true
	config.Security.Popularity = true
	config.Security.Geodiversity = true
	config.Security.GeodiversityNormalized = true
	config.Security.TLDGeodiversity = true
	config.Security.Geoscore = true
	config.Security.KSTest = true
	config.Security.Attack = true
	config.Security.ThreatType = true

	// if a field is configured to be fetched, but it is just
	// empty, it should still return blank fields
	secBlank := &goinvestigate.SecurityFeatures{
		DGAScore:               0.0,
		Perplexity:             0.0,
		Entropy:                0.0,
		SecureRank2:            0.0,
		PageRank:               0.0,
		ASNScore:               0.0,
		PrefixScore:            0.0,
		RIPScore:               0.0,
		Popularity:             0.0,
		Fastflux:               false,
		Geodiversity:           []goinvestigate.GeoFeatures{},
		GeodiversityNormalized: []goinvestigate.GeoFeatures{},
		TLDGeodiversity:        []goinvestigate.GeoFeatures{},
		Geoscore:               0,
		KSTest:                 0,
		Attack:                 "",
		ThreatType:             "",
	}
	ref = []string{
		"0", "0", "0", "0", "0", "0", "0", "0", "0",
		"false", "", "", "", "0", "0", "", "",
	}
	test, _ = config.ExtractCSVSubRow(secBlank)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
}

func TestExtractDomainTagInfo(t *testing.T) {
	dt := []goinvestigate.DomainTag{
		goinvestigate.DomainTag{
			Url:      "http://ancgrli.prophp.org/",
			Category: "Malware",
			Period: goinvestigate.PeriodType{
				Begin: "2014-04-07",
				End:   "Current",
			},
		},
		goinvestigate.DomainTag{
			Url:      "http://ancgrli.prophp.org/34/45791.html",
			Category: "Malware",
			Period: goinvestigate.PeriodType{
				Begin: "2014-03-04",
				End:   "2014-03-05",
			},
		},
	}

	ref := []string{
		"http://ancgrli.prophp.org/:Malware:2014-04-07:Current, " +
			"http://ancgrli.prophp.org/34/45791.html:Malware:2014-03-04:2014-03-05",
	}
	test, _ := config.ExtractCSVSubRow(dt)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// turn off Category and Begin
	config.TaggingDates.Category = false
	config.TaggingDates.Begin = false
	ref = []string{
		"http://ancgrli.prophp.org/:Current, " +
			"http://ancgrli.prophp.org/34/45791.html:2014-03-05",
	}
	test, _ = config.ExtractCSVSubRow(dt)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// turn off everything. Should return an empty slice
	config.TaggingDates.End = false
	config.TaggingDates.Url = false
	ref = []string{}
	test, _ = config.ExtractCSVSubRow(dt)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.TaggingDates.Category = true
	config.TaggingDates.Begin = true
	config.TaggingDates.End = true
	config.TaggingDates.Url = true

	// if a field is configured to be fetched, but it is just
	// empty, it should still return blank fields
	dtBlank := []goinvestigate.DomainTag{}
	ref = []string{""}
	test, _ = config.ExtractCSVSubRow(dtBlank)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
}

func TestExtractDomainRRHistoryInfo(t *testing.T) {
	hist := &goinvestigate.DomainRRHistory{
		RRPeriods: []goinvestigate.ResourceRecordPeriod{
			goinvestigate.ResourceRecordPeriod{
				FirstSeen: "2013-07-31",
				LastSeen:  "2013-10-17",
				RRs: []goinvestigate.ResourceRecord{
					goinvestigate.ResourceRecord{
						Name:  "example.com.",
						TTL:   86400,
						Class: "IN",
						Type:  "A",
						RR:    "93.184.216.119",
					},
				},
			},
			goinvestigate.ResourceRecordPeriod{
				FirstSeen: "2013-07-31",
				LastSeen:  "2013-10-17",
				RRs: []goinvestigate.ResourceRecord{
					goinvestigate.ResourceRecord{
						Name:  "example.com.",
						TTL:   86400,
						Class: "US",
						Type:  "A",
						RR:    "93.184.216.119",
					},
				},
			},
		},
		RRFeatures: goinvestigate.DomainResourceRecordFeatures{
			Age:           91,
			TTLsMin:       86400,
			TTLsMax:       172800,
			TTLsMean:      129600,
			TTLsMedian:    129600,
			TTLsStdDev:    43200,
			CountryCodes:  []string{"US"},
			ASNs:          []int{15133, 40528},
			Prefixes:      []string{"93.184.208.0", "192.0.43.0"},
			RIPSCount:     2,
			RIPSDiversity: 1,
			Locations: []goinvestigate.Location{
				goinvestigate.Location{
					Lat: 38.0,
					Lon: -97.0,
				},
				goinvestigate.Location{
					Lat: 33.78659999999999,
					Lon: -118.2987,
				},
			},
			GeoDistanceSum:  1970.1616237100388,
			GeoDistanceMean: 985.0808118550194,
			NonRoutable:     false,
			MailExchanger:   false,
			CName:           false,
			FFCandidate:     false,
			RIPSStability:   0.5,
			BaseDomain:      "example.com",
			IsSubdomain:     false,
		},
	}
	ref := []string{
		"2013-07-31:2013-10-17:example.com.:86400:IN:A:93.184.216.119, " +
			"2013-07-31:2013-10-17:example.com.:86400:US:A:93.184.216.119",
		"91", "86400", "172800", "129600", "129600", "43200",
		"US", "15133, 40528", "93.184.208.0, 192.0.43.0", "2", "1",
		"38:-97, 33.78659999999999:-118.2987",
		"1970.1616237100388", "985.0808118550194",
		"false", "false", "false", "false", "0.5", "example.com", "false",
	}
	test, _ := config.ExtractCSVSubRow(hist)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// couple of sanity checks. In RRHistory, only keep CountryCode
	// remove last 5 fields
	config.DomainRRHistory.Periods.Name = false
	config.DomainRRHistory.Periods.TTL = false
	config.DomainRRHistory.Periods.Type = false
	config.DomainRRHistory.Periods.RR = false
	config.DomainRRHistory.Features.NonRoutable = false
	config.DomainRRHistory.Features.MailExchanger = false
	config.DomainRRHistory.Features.CName = false
	config.DomainRRHistory.Features.FFCandidate = false
	config.DomainRRHistory.Features.RIPSStability = false
	config.DomainRRHistory.Features.BaseDomain = false
	config.DomainRRHistory.Features.IsSubdomain = false
	ref = []string{
		"2013-07-31:2013-10-17:IN, " +
			"2013-07-31:2013-10-17:US",
		"91", "86400", "172800", "129600", "129600", "43200",
		"US", "15133, 40528", "93.184.208.0, 192.0.43.0", "2", "1",
		"38:-97, 33.78659999999999:-118.2987",
		"1970.1616237100388", "985.0808118550194",
	}
	test, _ = config.ExtractCSVSubRow(hist)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.DomainRRHistory.Periods.Name = true
	config.DomainRRHistory.Periods.TTL = true
	config.DomainRRHistory.Periods.Type = true
	config.DomainRRHistory.Periods.RR = true
	config.DomainRRHistory.Features.NonRoutable = true
	config.DomainRRHistory.Features.MailExchanger = true
	config.DomainRRHistory.Features.CName = true
	config.DomainRRHistory.Features.FFCandidate = true
	config.DomainRRHistory.Features.RIPSStability = true
	config.DomainRRHistory.Features.BaseDomain = true
	config.DomainRRHistory.Features.IsSubdomain = true

	// everything off should return an empty list
	oldRRHist := config.DomainRRHistory
	config.DomainRRHistory = DomainRRHistoryConfig{}
	ref = []string{}
	test, _ = config.ExtractCSVSubRow(hist)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.DomainRRHistory = oldRRHist

	// if a field is configured to be fetched, but it is just
	// empty, it should still return blank fields
	histBlank := &goinvestigate.DomainRRHistory{
		RRPeriods: []goinvestigate.ResourceRecordPeriod{},
		RRFeatures: goinvestigate.DomainResourceRecordFeatures{
			Age:             0,
			TTLsMin:         0,
			TTLsMax:         0,
			TTLsMean:        0,
			TTLsMedian:      0,
			TTLsStdDev:      0,
			CountryCodes:    []string{},
			ASNs:            []int{},
			Prefixes:        []string{},
			RIPSCount:       0,
			RIPSDiversity:   0,
			Locations:       []goinvestigate.Location{},
			GeoDistanceSum:  0,
			GeoDistanceMean: 0,
			NonRoutable:     false,
			MailExchanger:   false,
			CName:           false,
			FFCandidate:     false,
			RIPSStability:   0,
			BaseDomain:      "",
			IsSubdomain:     false,
		},
	}
	ref = []string{
		"", "0", "0", "0", "0", "0", "0", "", "", "", "0", "0", "",
		"0", "0", "false", "false", "false", "false", "0", "", "false",
	}
	test, _ = config.ExtractCSVSubRow(histBlank)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
}
