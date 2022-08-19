package types

import "time"

const TimeLayout = "2006-01-02"

type CNNVDList struct {
	CNNVD []CNNVDEntry `xml:"entry"`
}
type OtherID struct {
	CVE string `xml:"cve-id"`
}
type CNNVDEntry struct {
	Name        string  `xml:"name"`
	CnnvdId     string  `xml:"vuln-id"`
	Published   string  `xml:"published"`
	Modified    string  `xml:"modified"`
	Severity    string  `xml:"severity"`
	Type        string  `xml:"vuln-type"`
	Description string  `xml:"vuln-descript"`
	Solution    string  `xml:"vuln-solution"`
	OtherID     OtherID `xml:"other-id"`
}

type CnnvdIns struct {
	Id          int64
	Name        string     `xorm:"text"`
	CnnvdId     string     `xorm:"varchar(55) index"`
	Published   *time.Time `xorm:"datetime"`
	Modified    *time.Time `xorm:"datetime"`
	Severity    string     `xorm:"text"`
	Type        string     `xorm:"text"`
	Description string     `xorm:"text"`
	Solution    string     `xorm:"text"`
	OtherID     string     `xorm:"text"`
}

func (e *CNNVDEntry) ToCnnvdIns() CnnvdIns {
	published, err := time.Parse("2006-01-02", e.Published)
	if err != nil {
		published = time.Now()
	}
	modefied, err := time.Parse("2006-01-02", e.Modified)
	if err != nil {
		modefied = time.Now()
	}
	cnnvdIns := CnnvdIns{
		Name:        e.Name,
		CnnvdId:     e.CnnvdId,
		Published:   &published,
		Modified:    &modefied,
		Severity:    e.Severity,
		Type:        e.Type,
		Description: e.Description,
		Solution:    e.Solution,
		OtherID:     e.OtherID.CVE,
	}
	return cnnvdIns
}

func (i *CnnvdIns) ToVemindVulnerability() VeinmindVulnerability {
	veinmindVulnerability := VeinmindVulnerability{
		CveId:         "NONE",
		CnvdId:        "NONE",
		CnnvdId:       i.CnnvdId,
		TitileZn:      i.Name,
		DescZn:        i.Description,
		PublishedDate: i.Published,
		SeverityStr:   i.Severity,
		VulnType:      i.Type,
		FormalWay:     i.Solution,
	}
	return veinmindVulnerability
}
