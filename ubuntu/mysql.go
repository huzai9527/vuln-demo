package ubuntu

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"vuln-list-update/types"

	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/xerrors"
	"xorm.io/xorm"
)

const (
	ubuntuDir      = "ubuntu"
	platformFormat = "ubuntu %s"
)

var (
	targetStatuses        = []string{"needed", "deferred", "released"}
	UbuntuReleasesMapping = map[string]string{
		"precise": "12.04",
		"quantal": "12.10",
		"raring":  "13.04",
		"saucy":   "13.10",
		"trusty":  "14.04",
		"utopic":  "14.10",
		"vivid":   "15.04",
		"wily":    "15.10",
		"xenial":  "16.04",
		"yakkety": "16.10",
		"zesty":   "17.04",
		"artful":  "17.10",
		"bionic":  "18.04",
		"cosmic":  "18.10",
		"disco":   "19.04",
		"eoan":    "19.10",
		"focal":   "20.04",
		"groovy":  "20.10",
		"hirsute": "21.04",
		"impish":  "21.10",
		"jammy":   "22.04",
		// ESM versions:
		"precise/esm":      "12.04-ESM",
		"trusty/esm":       "14.04-ESM",
		"esm-infra/xenial": "16.04-ESM",
	}
)

type Mysql struct {
	Engine *xorm.Engine
}

func (m *Mysql) Init(dsn string) (err error) {
	engine, err := xorm.NewEngine("mysql", dsn)
	if err != nil {
		return err
	}
	// 这里应该在最开始的时候删除，中间过程中不可以删除
	// 否则会丢失数据，这里目前只有nvd，方便调试
	if err := engine.DropTables(new(types.VulnerabilityDetail), new(types.Advisory)); err != nil {
		return err
	}
	if err := engine.Sync2(new(types.VulnerabilityDetail), new(types.Advisory)); err != nil {
		return err
	}
	m.Engine = engine
	return nil
}

func (o *Mysql) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", ubuntuDir)
	var cves []ubuntu.UbuntuCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve ubuntu.UbuntuCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Ubuntu JSON: %w", err)
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Ubuntu walk: %w", err)
	}

	if err = o.save(cves); err != nil {
		return xerrors.Errorf("error in Ubuntu save: %w", err)
	}

	return nil
}

func (o *Mysql) save(cves []ubuntu.UbuntuCVE) error {
	for _, cve := range cves {
		for packageName, patch := range cve.Patches {
			pkgName := string(packageName)
			for release, status := range patch {
				if !strings.InSlice(status.Status, targetStatuses) {
					continue
				}
				osVersion, ok := UbuntuReleasesMapping[string(release)]
				if !ok {
					continue
				}
				platformName := fmt.Sprintf(platformFormat, osVersion)
				adv := types.Advisory{
					PlatformName:    platformName,
					VulnerabilityID: cve.Candidate,
					PackageName:     pkgName,
				}
				if status.Status == "released" {
					adv.FixedVersion = status.Note
				}
				if _, err := o.Engine.Insert(adv); err != nil {
					return xerrors.Errorf("failed to save Ubuntu advisory: %w", err)
				}
				vuln := types.VulnerabilityDetail{
					CveId:       cve.Candidate,
					Severity:    SeverityFromPriority(cve.Priority),
					References:  cve.References,
					Description: cve.Description,
				}
				if _, err := o.Engine.Insert(vuln); err != nil {
					xerrors.Errorf("failed to save Ubuntu vulnerability: %w", err)
				}
			}
		}
	}

	return nil
}

// SeverityFromPriority converts Ubuntu priority into Trivy severity
func SeverityFromPriority(priority string) types.Severity {
	switch priority {
	case "untriaged":
		return types.SeverityUnknown
	case "negligible", "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
