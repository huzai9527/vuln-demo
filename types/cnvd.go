package types

import "encoding/xml"

type CNVDList struct {
	XMLName xml.Name `xml:"vulnerabilitys"`
	CNVD    []Cnvd   `xml:"vulnerability"`
}
type ProductEntry struct {
	Product []string `xml:"product"`
}

type Cve struct {
	CveNumber string `xml:"cveNumber" xorm:"text"`
}
type CveEntry struct {
	Cve []Cve `xml:"cve"`
}

type Cnvd struct {
	Name             string       `xml:"title" xorm:"text"`
	CnvdId           string       `xml:"number" xorm:"text"`
	OpenTime         string       `xml:"openTime" xorm:"text"`
	SubmitTime       string       `xml:"submitTime" xorm:"text"`
	Severity         string       `xml:"severity" xorm:"text"`
	IsEvent          string       `xml:"isEvent" xorm:"text"`
	Description      string       `xml:"description" xorm:"text"`
	FormalWay        string       `xml:"formalWay" xorm:"text"`
	ProductEntry     ProductEntry `xml:"products" `
	CveEntry         CveEntry     `xml:"cves" `
	DiscovererName   string       `xml:"discovererName" xorm:"text"`
	ReferenceLink    string       `xml:"referenceLink" xorm:"text"`
	PatchName        string       `xml:"patchName" xorm:"text"`
	PatchDescription string       `xml:"patchDescription" xorm:"text"`
}

type CnvdIns struct {
	Id               int64
	Name             string `xorm:"text"`
	CnvdId           string `xorm:"text"`
	OpenTime         string `xorm:"text"`
	SubmitTime       string `xorm:"text"`
	Severity         string `xorm:"text"`
	IsEvent          string `xorm:"text"`
	Description      string `xorm:"text"`
	FormalWay        string `xorm:"text"`
	ProductEntry     string `xorm:"text"`
	CveEntry         string `xorm:"text"`
	DiscovererName   string `xorm:"text"`
	ReferenceLink    string `xorm:"text"`
	PatchName        string `xorm:"text"`
	PatchDescription string `xorm:"text"`
}

func (cnvd *Cnvd) ToCnvdIns() CnvdIns {
	cnvdIns := CnvdIns{
		Name:             cnvd.Name,
		CnvdId:           cnvd.CnvdId,
		OpenTime:         cnvd.OpenTime,
		SubmitTime:       cnvd.SubmitTime,
		Severity:         cnvd.Severity,
		IsEvent:          cnvd.IsEvent,
		Description:      cnvd.Description,
		FormalWay:        cnvd.FormalWay,
		ProductEntry:     cnvd.ProductEntry.toString(),
		CveEntry:         cnvd.CveEntry.toString(),
		DiscovererName:   cnvd.DiscovererName,
		ReferenceLink:    cnvd.ReferenceLink,
		PatchName:        cnvd.PatchName,
		PatchDescription: cnvd.PatchDescription,
	}
	return cnvdIns
}

func (e *ProductEntry) toString() string {
	s := ""
	for _, item := range e.Product {
		s = s + item + ";"
	}
	return s
}
func (e *CveEntry) toString() string {
	s := ""
	for _, item := range e.Cve {
		s = s + item.CveNumber + ";"
	}
	return s
}

func (v *CnvdIns) ToVemindVulnerability() VeinmindVulnerability {
	veinmindVulnerability := VeinmindVulnerability{
		CveId:            "NONE",
		CnvdId:           v.CnvdId,
		TitileZn:         v.Name,
		DescZn:           v.Description,
		PatchName:        v.PatchName,
		PatchDescription: v.PatchDescription,
		References:       []string{v.ReferenceLink},
		FormalWay:        v.FormalWay,
	}
	return veinmindVulnerability
}
