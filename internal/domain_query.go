package domainstats

import "github.com/dead10ck/goinvestigate"

type DomainQueryType interface {
	Query() DomainQueryResponse
}

type DomainQuery struct {
	Inv    *goinvestigate.Investigate
	Domain string
}

type DomainQueryMessage struct {
	Q        DomainQueryType
	RespChan chan DomainQueryResponse
}

type DomainQueryResponse struct {
	Resp interface{}
	Err  error
}

type CategorizationQuery struct {
	DomainQuery
	Labels bool
}

func (q *CategorizationQuery) Query() DomainQueryResponse {
	resp, err := q.Inv.Categorization(q.Domain, q.Labels)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type RelatedQuery struct {
	DomainQuery
}

func (q *RelatedQuery) Query() DomainQueryResponse {
	resp, err := q.Inv.RelatedDomains(q.Domain)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type CooccurrencesQuery struct {
	DomainQuery
}

func (q *CooccurrencesQuery) Query() DomainQueryResponse {
	resp, err := q.Inv.RelatedDomains(q.Domain)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type SecurityQuery struct {
	DomainQuery
}

func (q *SecurityQuery) Query() DomainQueryResponse {
	resp, err := q.Inv.Security(q.Domain)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type DomainTagsQuery struct {
	DomainQuery
}

func (q *DomainTagsQuery) Query() DomainQueryResponse {
	resp, err := q.Inv.DomainTags(q.Domain)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type DomainRRHistoryQuery struct {
	DomainQuery
	QueryType string
}

func (q *DomainRRHistoryQuery) Query() DomainQueryResponse {
	resp, err := q.Inv.DomainRRHistory(q.Domain, q.QueryType)
	return DomainQueryResponse{Resp: resp, Err: err}
}
