package nvd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"vuln-list-update/types"

	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/nvd"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/xerrors"
	"xorm.io/xorm"
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
	if err := engine.DropTables(new(types.VulnerabilityDetail)); err != nil {
		return err
	}
	if err := engine.Sync2(new(types.VulnerabilityDetail)); err != nil {
		return err
	}
	m.Engine = engine
	return nil
}

const (
	nvdDir = "nvd"
)

func (m *Mysql) Update(dir string) error {
	var items []nvd.Item
	buffer := &bytes.Buffer{}
	err := utils.FileWalk(dir, func(r io.Reader, _ string) error {
		item := nvd.Item{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return xerrors.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(buffer.Bytes(), &item); err != nil {
			return xerrors.Errorf("failed to decode NVD JSON: %w", err)
		}
		buffer.Reset()
		items = append(items, item)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in NVD walk: %w", err)
	}

	if err = m.commit(items); err != nil {
		return xerrors.Errorf("error in NVD save: %w", err)
	}

	return nil
}

func (m *Mysql) commit(items []nvd.Item) error {
	for _, item := range items {
		cveID := item.Cve.Meta.ID
		severity, _ := types.NewSeverity(item.Impact.BaseMetricV2.Severity)
		severityV3, _ := types.NewSeverity(item.Impact.BaseMetricV3.CvssV3.BaseSeverity)

		var references []string
		for _, ref := range item.Cve.References.ReferenceDataList {
			references = append(references, ref.URL)
		}

		var (
			description string
		)
		for _, d := range item.Cve.Description.DescriptionDataList {
			if d.Value != "" {
				description = d.Value
				break
			}
		}
		var cweIDs []string
		for _, data := range item.Cve.ProblemType.ProblemTypeData {
			for _, desc := range data.Description {
				if !strings.HasPrefix(desc.Value, "CWE") {
					continue
				}
				cweIDs = append(cweIDs, desc.Value)
			}
		}

		publishedDate, _ := time.Parse("2006-01-02T15:04Z", item.PublishedDate)
		lastModifiedDate, _ := time.Parse("2006-01-02T15:04Z", item.LastModifiedDate)

		vuln := types.VulnerabilityDetail{
			CveId:            cveID,
			CvssScore:        item.Impact.BaseMetricV2.CvssV2.BaseScore,
			CvssVector:       item.Impact.BaseMetricV2.CvssV2.VectorString,
			CvssScoreV3:      item.Impact.BaseMetricV3.CvssV3.BaseScore,
			CvssVectorV3:     item.Impact.BaseMetricV3.CvssV3.VectorString,
			Severity:         severity,
			SeverityV3:       severityV3,
			CweIds:           cweIDs,
			References:       references,
			Title:            "",
			Description:      description,
			PublishedDate:    &publishedDate,
			LastModifiedDate: &lastModifiedDate,
		}
		if _, err := m.Engine.Insert(vuln); err != nil {
			fmt.Println(err)
			return err
		}
	}
	return nil
}
