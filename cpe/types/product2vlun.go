package types

type Product2Vuln struct {
	Id                   int64
	ProductId            int64    `xorm:"int"`
	VulnId               int64    `xorm:"int"`
	AffectedVersionRange []string `xorm:"text"`
	AffectedVersionSet   []string
	AffectedArchs        []string `xorm:"text"`
}
