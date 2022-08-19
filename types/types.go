package types

import (
	"fmt"
	"time"
)

type Severity int

type VendorSeverity map[SourceID]Severity

//CVSS 漏洞评分等级，有几种表达方式（nvd/redhat）
type CVSS struct {
	V2Vector string  `json:"V2Vector,omitempty" xorm:"varchar(255)"`
	V3Vector string  `json:"V3Vector,omitempty" xorm:"varchar(255)"`
	V2Score  float64 `json:"V2Score,omitempty" xorm:"float"`
	V3Score  float64 `json:"V3Score,omitempty" xorm:"float"`
}

type CVSSVector struct {
	V2 string `json:"v2,omitempty" xorm:"varchar(255)"`
	V3 string `json:"v3,omitempty" xorm:"varchar(255)"`
}

type VendorCVSS map[SourceID]CVSS

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var (
	SeverityNames = []string{
		"UNKNOWN",
		"LOW",
		"MEDIUM",
		"HIGH",
		"CRITICAL",
	}
)

func NewSeverity(severity string) (Severity, error) {
	for i, name := range SeverityNames {
		if severity == name {
			return Severity(i), nil
		}
	}
	return SeverityUnknown, fmt.Errorf("unknown severity: %s", severity)
}

func CompareSeverityString(sev1, sev2 string) int {
	s1, _ := NewSeverity(sev1)
	s2, _ := NewSeverity(sev2)
	return int(s2) - int(s1)
}

func (s Severity) String() string {
	return SeverityNames[s]
}

type LastUpdated struct {
	Date time.Time
}

// VulnerabilityDetail 漏洞的详细信息
type VulnerabilityDetail struct {
	Id int64 `json:",omitempty" `
	// CVE编号
	CveId string `json:",omitempty" xorm:"varchar(255)"` // e.g. CVE-2019-8331, OSVDB-104365
	// 漏洞评分等级，有几种表达方式（nvd/redhat）
	// 不同厂商会有不一样的评分
	CvssScore    float64 `json:",omitempty" xorm:"float"`
	CvssVector   string  `json:",omitempty" xorm:"varchar(255)"`
	CvssScoreV3  float64 `json:",omitempty" xorm:"float"`
	CvssVectorV3 string  `json:",omitempty" xorm:"varchar(255)"`
	// 风险等级
	Severity   Severity `json:",omitempty" xorm:"text"`
	SeverityV3 Severity `json:",omitempty" xorm:"text"`
	// 漏洞相关的CWE编号ID
	CweIds []string `json:",omitempty" xorm:"text"` // e.g. CWE-78, CWE-89
	// 相关的参考连接
	References []string `json:",omitempty" xorm:"text"`
	// 漏洞标题
	Title string `json:",omitempty" xorm:"text"`
	// 漏洞描述
	Description string `json:",omitempty" xorm:"text"`
	// 漏洞披露时间
	PublishedDate *time.Time `json:",omitempty" xorm:"datetime"` // Take from NVD
	// 漏洞信息最后被修改的时间
	LastModifiedDate *time.Time `json:",omitempty" xorm:"datetime"` // Take from NVD

}

// AdvisoryDetail 对应os-release 下 pkg 可能存在的漏洞
type AdvisoryDetail struct {
	PlatformName string
	PackageName  string
	AdvisoryItem interface{}
}

// SourceID represents data source such as NVD.
type SourceID string

// DataSource 漏洞信息来源
type DataSource struct {
	ID   SourceID `json:",omitempty" xorm:"text"`
	Name string   `json:",omitempty" xorm:"text"`
	URL  string   `json:",omitempty" xorm:"text"`
}

// Advisory 有关漏洞的建议，实际上是初筛报告
// 后面会根据的版本进行筛选
type Advisory struct {
	// 用于sql主键递增
	Id int64 `json:",omitempty" `
	// 不同的平台名称
	PlatformName string `json:",omitempty" xorm:"text"`
	// pkg名称
	PackageName string `json:",omitempty" xorm:"text"`
	// 对应的CVE ID
	VulnerabilityId string `json:",omitempty" xorm:"text"` // CVE-ID or vendor ID
	// 其他的厂商对应的ID
	VendorIds []string `json:",omitempty" xorm:"text"` // e.g. RHSA-ID and DSA-ID
	// 不同的架构 ubuntu x86 和 arm
	// Rpm packages have advisories for different architectures with same package name
	// This field is required to separate these packages.
	Arches []string `json:"-" xorm:"text"`
	// 软件目前的状态
	// It is filled only when FixedVersion is empty since it is obvious the state is "Fixed" when FixedVersion is not empty.
	// e.g. Will not fix and Affected
	State string `json:",omitempty" xorm:"text"`
	// 风险等级
	// Trivy DB has "vulnerability" bucket and severities are usually stored in the bucket per a vulnerability ID.
	// In some cases, the advisory may have multiple severities depending on the packages.
	// For example, CVE-2015-2328 in Debian has "unimportant" for mongodb and "low" for pcre3.
	// e.g. https://security-tracker.debian.org/tracker/CVE-2015-2328
	Severity Severity `json:",omitempty" xorm:"text"`
	// 修复的版本以及受影响的版本
	// Versions for os package
	FixedVersion    string `json:",omitempty" xorm:"varchar(255)"`
	AffectedVersion string `json:",omitempty" xorm:"varchar(255)"` // Only for Arch Linux
	// 补丁相关的信息
	// MajorVersion ranges for language-specific package
	// Some advisories provide VulnerableVersions only, others provide PatchedVersions and UnaffectedVersions
	VulnerableVersions []string `json:",omitempty" xorm:"text"`
	PatchedVersions    []string `json:",omitempty" xorm:"text"`
	UnaffectedVersions []string `json:",omitempty" xorm:"text"`
	// 数据来源
	// DataSource holds where the advisory comes from
	DataSource *DataSource `json:",omitempty" xorm:"text"`

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom interface{} `json:",omitempty" xorm:"text"`
}

type Vulnerability struct {
	Title            string         `json:",omitempty" xorm:"text"`
	Description      string         `json:",omitempty" xorm:"text"`
	Severity         string         `json:",omitempty" xorm:"text"` // Selected from VendorSeverity, depending on a scan target
	CweIds           []string       `json:",omitempty" xorm:"text"` // e.g. CWE-78, CWE-89
	VendorSeverity   VendorSeverity `json:",omitempty" xorm:"text"`
	CVSS             VendorCVSS     `json:",omitempty" xorm:"text"`
	References       []string       `json:",omitempty" xorm:"text"`
	PublishedDate    *time.Time     `json:",omitempty" xorm:"datetime"` // Take from NVD
	LastModifiedDate *time.Time     `json:",omitempty" xorm:"datetime"` // Take from NVD

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom interface{} `json:",omitempty" xorm:"text"`
}

// Ecosystem represents language-specific ecosystem
type Ecosystem string

func (v *VulnerabilityDetail) ToVemindVulnerability() VeinmindVulnerability {
	veinmindVulnerability := VeinmindVulnerability{
		CveId:            v.CveId,
		TitleEn:          v.Title,
		DescEn:           v.Description,
		PublishedDate:    v.PublishedDate,
		LastModifiedDate: v.LastModifiedDate,
		Severity:         v.Severity,
		CvssScoreV3:      v.CvssScoreV3,
		CvssScore:        v.CvssScore,
		CvssVector:       v.CvssVector,
		CvssVectorV3:     v.CvssVectorV3,
		References:       v.References,
		Cwes:             v.CweIds,
	}
	return veinmindVulnerability
}

type Mysql interface {
	Init(dsn string) error
	Update(dir string) error
}
