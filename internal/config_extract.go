package domainstats

import (
	"errors"
	"strconv"
	"strings"

	"github.com/dead10ck/goinvestigate"
)

// Uses a goinvestigate response to derive the field values to go in a
// CSV row. Once all responses are processed with this function, the
// []string results can be concatenated to yield the final CSV row.
func (c *Config) ExtractCSVSubRow(goinvResp interface{}) (row []string, err error) {
	switch resp := goinvResp.(type) {
	case *goinvestigate.DomainCategorization:
		return c.extractDomainCatInfo(resp), nil
	case []goinvestigate.RelatedDomain:
		return c.extractRelatedDomainInfo(resp), nil
	case []goinvestigate.Cooccurrence:
		return c.extractCooccurrenceInfo(resp), nil
	case *goinvestigate.SecurityFeatures:
		return c.extractSecurityFeaturesInfo(resp), nil
	case []goinvestigate.DomainTag:
		return c.extractDomainTagInfo(resp), nil
	case *goinvestigate.DomainRRHistory:
		return c.extractDomainRRHistoryInfo(resp), nil
	default:
		return nil, errors.New("invalid type")
	}
}

func (c *Config) extractDomainCatInfo(resp *goinvestigate.DomainCategorization) []string {
	var row []string
	if c.Status {
		row = append(row, strconv.Itoa(resp.Status))
	}

	if c.Categories.SecurityCategories {
		row = append(row, strings.Join(resp.SecurityCategories, ", "))
	}

	if c.Categories.ContentCategories {
		row = append(row, strings.Join(resp.ContentCategories, ", "))
	}

	return row
}

// dynamic field. Should return a singleton list
func (c *Config) extractRelatedDomainInfo(resp []goinvestigate.RelatedDomain) []string {
	if len(resp) == 0 && any(c.Related) {
		return []string{""}
	}
	row := []string{}
	for _, rd := range resp {
		if c.Related.Domain {
			row = append(row, rd.Domain)
			if c.Related.Score {
				row[len(row)-1] += ":"
			}
		} else if c.Related.Score {
			row = append(row, "")
		}
		if c.Related.Score {
			row[len(row)-1] += strconv.Itoa(rd.Score)
		}
	}
	if len(row) == 0 {
		return []string{}
	}
	return []string{strings.Join(row, ", ")}
}

// dynamic field. Should return a singleton list
func (c *Config) extractCooccurrenceInfo(resp []goinvestigate.Cooccurrence) []string {
	if len(resp) == 0 && any(c.Cooccurrences) {
		return []string{""}
	}
	row := []string{}
	for _, cooc := range resp {
		if c.Cooccurrences.Domain {
			row = append(row, cooc.Domain)
			if c.Cooccurrences.Score {
				row[len(row)-1] += ":"
			}
		} else if c.Cooccurrences.Score {
			row = append(row, "")
		}
		if c.Cooccurrences.Score {
			row[len(row)-1] += convertFloatToStr(cooc.Score)
		}
	}
	if len(row) == 0 {
		return []string{}
	}
	return []string{strings.Join(row, ", ")}
}

// partially dynamic. Geo* fields are single fields
func (c *Config) extractSecurityFeaturesInfo(resp *goinvestigate.SecurityFeatures) []string {
	row := []string{}
	row = appendIf(row, convertFloatToStr(resp.DGAScore), c.Security.DGAScore)
	row = appendIf(row, convertFloatToStr(resp.Perplexity), c.Security.Perplexity)
	row = appendIf(row, convertFloatToStr(resp.Entropy), c.Security.Entropy)
	row = appendIf(row, convertFloatToStr(resp.SecureRank2), c.Security.SecureRank2)
	row = appendIf(row, convertFloatToStr(resp.PageRank), c.Security.PageRank)
	row = appendIf(row, convertFloatToStr(resp.ASNScore), c.Security.ASNScore)
	row = appendIf(row, convertFloatToStr(resp.PrefixScore), c.Security.PrefixScore)
	row = appendIf(row, convertFloatToStr(resp.RIPScore), c.Security.RIPScore)
	row = appendIf(row, convertFloatToStr(resp.Popularity), c.Security.Popularity)
	row = appendIf(row, strconv.FormatBool(resp.Fastflux), c.Security.Fastflux)
	row = appendIf(row, geoString(resp.Geodiversity), c.Security.Geodiversity)
	row = appendIf(row, geoString(resp.GeodiversityNormalized), c.Security.GeodiversityNormalized)
	row = appendIf(row, geoString(resp.TLDGeodiversity), c.Security.TLDGeodiversity)
	row = appendIf(row, convertFloatToStr(resp.Geoscore), c.Security.Geoscore)
	row = appendIf(row, convertFloatToStr(resp.KSTest), c.Security.KSTest)
	row = appendIf(row, resp.Attack, c.Security.Attack)
	row = appendIf(row, resp.ThreatType, c.Security.ThreatType)
	return row
}

// dynamic field. Should return a singleton list
func (c *Config) extractDomainTagInfo(resp []goinvestigate.DomainTag) []string {
	if !any(c.TaggingDates) {
		return []string{}
	}

	dtStrs := []string{}
	for _, dt := range resp {
		fieldStrs := []string{}
		fieldStrs = appendIf(fieldStrs, dt.Url, c.TaggingDates.Url)
		fieldStrs = appendIf(fieldStrs, dt.Category, c.TaggingDates.Category)
		fieldStrs = appendIf(fieldStrs, dt.Period.Begin, c.TaggingDates.Begin)
		fieldStrs = appendIf(fieldStrs, dt.Period.End, c.TaggingDates.End)
		if len(fieldStrs) != 0 {
			dtStrs = append(dtStrs, strings.Join(fieldStrs, ":"))
		}
	}

	// if any fields are configured to be fetched from Tagging Dates,
	// but there just happens to not be any info for this domain,
	// return a blank field
	if len(dtStrs) == 0 && any(c.TaggingDates) {
		return []string{""}
	}

	return []string{strings.Join(dtStrs, ", ")}
}

func (c *Config) extractDomainRRHistoryInfo(resp *goinvestigate.DomainRRHistory) []string {
	row := []string{}

	// if no fields from the RRPeriods are configured to be fetched, don't
	// try to convert it at all - just skip it
	// If they ARE configured as such, but there just happens to not be any periods
	// in the response data, it will append an empty string
	if any(c.DomainRRHistory.Periods) {
		rrPeriodsStr := c.rrPeriodsToStr(resp.RRPeriods)
		row = append(row, rrPeriodsStr)
	}

	row = appendIf(row, strconv.Itoa(resp.RRFeatures.Age), c.DomainRRHistory.Features.Age)
	row = appendIf(row, strconv.Itoa(resp.RRFeatures.TTLsMin), c.DomainRRHistory.Features.TTLsMin)
	row = appendIf(row, strconv.Itoa(resp.RRFeatures.TTLsMax), c.DomainRRHistory.Features.TTLsMax)
	row = appendIf(row, convertFloatToStr(resp.RRFeatures.TTLsMean), c.DomainRRHistory.Features.TTLsMean)
	row = appendIf(row, convertFloatToStr(resp.RRFeatures.TTLsMedian), c.DomainRRHistory.Features.TTLsMedian)
	row = appendIf(row, convertFloatToStr(resp.RRFeatures.TTLsStdDev), c.DomainRRHistory.Features.TTLsStdDev)
	row = appendIf(row, strings.Join(resp.RRFeatures.CountryCodes, ", "), c.DomainRRHistory.Features.CountryCodes)

	asnStrs := []string{}
	for _, asn := range resp.RRFeatures.ASNs {
		asnStrs = append(asnStrs, strconv.Itoa(asn))
	}

	row = appendIf(row, strings.Join(asnStrs, ", "), c.DomainRRHistory.Features.ASNs)
	row = appendIf(row, strings.Join(resp.RRFeatures.Prefixes, ", "), c.DomainRRHistory.Features.Prefixes)
	row = appendIf(row, strconv.Itoa(resp.RRFeatures.RIPSCount), c.DomainRRHistory.Features.RIPSCount)
	row = appendIf(row, convertFloatToStr(resp.RRFeatures.RIPSDiversity), c.DomainRRHistory.Features.RIPSDiversity)
	row = appendIf(row, locsToStr(resp.RRFeatures.Locations), c.DomainRRHistory.Features.Locations)
	row = appendIf(row, convertFloatToStr(resp.RRFeatures.GeoDistanceSum), c.DomainRRHistory.Features.GeoDistanceSum)
	row = appendIf(row, convertFloatToStr(resp.RRFeatures.GeoDistanceMean), c.DomainRRHistory.Features.GeoDistanceMean)
	row = appendIf(row, strconv.FormatBool(resp.RRFeatures.NonRoutable), c.DomainRRHistory.Features.NonRoutable)
	row = appendIf(row, strconv.FormatBool(resp.RRFeatures.MailExchanger), c.DomainRRHistory.Features.MailExchanger)
	row = appendIf(row, strconv.FormatBool(resp.RRFeatures.CName), c.DomainRRHistory.Features.CName)
	row = appendIf(row, strconv.FormatBool(resp.RRFeatures.FFCandidate), c.DomainRRHistory.Features.FFCandidate)
	row = appendIf(row, convertFloatToStr(resp.RRFeatures.RIPSStability), c.DomainRRHistory.Features.RIPSStability)
	row = appendIf(row, resp.RRFeatures.BaseDomain, c.DomainRRHistory.Features.BaseDomain)
	row = appendIf(row, strconv.FormatBool(resp.RRFeatures.IsSubdomain), c.DomainRRHistory.Features.IsSubdomain)
	return row
}

func locsToStr(locs []goinvestigate.Location) string {
	strs := []string{}
	for _, loc := range locs {
		locStrs := []string{}
		locStrs = append(locStrs, convertFloatToStr(loc.Lat))
		locStrs = append(locStrs, convertFloatToStr(loc.Lon))
		strs = append(strs, strings.Join(locStrs, ":"))
	}
	return strings.Join(strs, ", ")
}

func (c *Config) rrPeriodsToStr(periods []goinvestigate.ResourceRecordPeriod) string {

	periodStrs := []string{}
	for _, p := range periods {
		flStrs := []string{}
		flStrs = appendIf(flStrs, p.FirstSeen, c.DomainRRHistory.Periods.FirstSeen)
		flStrs = appendIf(flStrs, p.LastSeen, c.DomainRRHistory.Periods.LastSeen)
		for _, rr := range p.RRs {
			rrStrs := []string{}
			rrStrs = appendIf(rrStrs, rr.Name, c.DomainRRHistory.Periods.Name)
			rrStrs = appendIf(rrStrs, strconv.Itoa(rr.TTL), c.DomainRRHistory.Periods.TTL)
			rrStrs = appendIf(rrStrs, rr.Class, c.DomainRRHistory.Periods.Class)
			rrStrs = appendIf(rrStrs, rr.Type, c.DomainRRHistory.Periods.Type)
			rrStrs = appendIf(rrStrs, rr.RR, c.DomainRRHistory.Periods.RR)

			flrr := append(flStrs, rrStrs...)
			if len(flrr) != 0 {
				periodStrs = append(periodStrs, strings.Join(flrr, ":"))
			}
		}
	}

	// otherwise, return an empty slice
	return strings.Join(periodStrs, ", ")
}

func geoString(gs []goinvestigate.GeoFeatures) string {
	strs := []string{}
	for _, g := range gs {
		score := strconv.FormatFloat(g.VisitRatio, 'f', -1, 64)
		strs = append(strs, strings.Join([]string{g.CountryCode, score}, ":"))
	}
	return strings.Join(strs, ", ")
}

// Appends appendVal to source if cond is true and returns the resulting slice.
// Otherwise, returns source as-is.
func appendIf(source []string, appendVal string, cond bool) []string {
	if cond {
		return append(source, appendVal)
	}
	return source
}

// convenience central wrapper around strconv.FormatFloat(),
// just in case one of these parameters needs to be changed at some point
func convertFloatToStr(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
