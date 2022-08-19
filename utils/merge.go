package utils

import (
	"fmt"
	"strings"
	"vuln-list-update/types"

	_ "github.com/go-sql-driver/mysql"
	"xorm.io/xorm"
)

type Merge struct {
	Engine *xorm.Engine
}

func (m *Merge) Init(dsn string) error {
	engine, err := xorm.NewEngine("mysql", dsn)
	if err != nil {
		return err
	}
	if err := engine.DropTables(new(types.VeinmindVulnerability)); err != nil {
		return err
	}
	if err := engine.Sync2(new(types.CnvdIns), new(types.VulnerabilityDetail), new(types.VeinmindVulnerability)); err != nil {
		return err
	}
	if err := engine.Sync2(new(types.CnnvdIns)); err != nil {
		return err
	}
	m.Engine = engine
	return nil
}
func (m *Merge) MergeAll() error {
	fmt.Println("start merge...")
	err := m.mergeNvd()
	if err != nil {
		return err
	}
	err = m.mergeCnvd()
	if err != nil {
		return err
	}
	err = m.mergeCnnvd()
	if err != nil {
		return err
	}
	return nil
}

// 直接将 nvd 表中的信息插入 veinmid 表中
func (m *Merge) mergeNvd() error {
	var maxId int64
	has, err := m.Engine.SQL("select max(id) from vulnerability_detail").Get(&maxId)
	if err != nil {
		return err
	}
	if has {
		for id := 1; id <= int(maxId); id++ {
			vuln := new(types.VulnerabilityDetail)
			m.Engine.ID(id).Get(vuln)
			m.Engine.Insert(vuln.ToVemindVulnerability())
		}
	}
	return nil
}

// 将 cnvd 的信息，按条插入 veinmind 表中
// 如果某条 cnvd 没有对应的 cveid ，则直接将其插入 veinmind 表中
// 如果在 veinmind 中存在与之对应的 cveid 则将 cnvd 提供的中文信息插入 veinmind
func (m *Merge) mergeCnvd() error {
	var maxId int64
	has, err := m.Engine.SQL("select max(id) from cnvd_ins").Get(&maxId)
	if err != nil {
		return err
	}
	if has {
		for id := 1; id <= int(maxId); id++ {
			cnvd := new(types.CnvdIns)
			_, err := m.Engine.ID(id).Get(cnvd)
			if err != nil {
				continue
			}
			err = m.UpdateVeinmindVulnTableByCnvd(*cnvd)
			if err != nil {
				continue
			}
		}
	}
	return nil
}

// 通过某条 cnvd 信息更新 veinmind 表
func (m *Merge) UpdateVeinmindVulnTableByCnvd(cnvd types.CnvdIns) error {
	vulns := m.findVeinmindVulnByCveIds(cnvd.CveEntry)
	if len(vulns) == 0 {
		return m.insertCvnd(cnvd)
	}
	for _, vuln := range vulns {
		err := m.updateVeinmindVulnTableByCnvd(vuln, cnvd)
		if err != nil {
			continue
		}
	}
	return nil
}

// 如果此条 cnvd 信息还未插入 veinmind，则插入，否则直接返回
func (m *Merge) insertCvnd(cnvd types.CnvdIns) error {
	has, err := m.Engine.SQL("select * from veinmind_vulnerability where cnvd_id = \"" + cnvd.CnvdId + "\"").Get(&cnvd)
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = m.Engine.Insert(cnvd.ToVemindVulnerability())
	if err != nil {
		return err
	}
	return nil
}

// 根据 cnvd 中的 cveEntry 查询 veinmind 表中对应的条目
func (m *Merge) findVeinmindVulnByCveIds(ids string) (VeinmindVulnerabilities []types.VeinmindVulnerability) {
	if ids == "" {
		return []types.VeinmindVulnerability{}
	}
	cveIds := strings.Split(ids, ";")
	for _, cveId := range cveIds {
		data := make([]types.VeinmindVulnerability, 0)
		err := m.Engine.SQL("select * from veinmind_vulnerability where cve_id = \"" + cveId + "\"").Find(&data)
		if err != nil {
			continue
		}
		VeinmindVulnerabilities = append(VeinmindVulnerabilities, data...)
	}
	return VeinmindVulnerabilities
}

// 根据 cnvd 的信息更新 veinmind 表
func (m *Merge) updateVeinmindVulnTableByCnvd(vuln types.VeinmindVulnerability, cnvd types.CnvdIns) error {
	vuln.CnvdId = cnvd.CnvdId
	vuln.DescZn = cnvd.Description
	vuln.TitileZn = cnvd.Name
	vuln.PatchName = cnvd.PatchName
	vuln.PatchDescription = cnvd.PatchDescription
	vuln.FormalWay = cnvd.FormalWay
	_, err := m.Engine.ID(vuln.Id).Update(vuln)
	if err != nil {
		return err
	}
	return nil
}

// 遍历 Cnnvd 表中的条目
// 如果当前条目没有对应的 cveid，并且没有被插入 veinmind，则直接插入
// 如果当前条目有对应的 cveid 但没有 Cnvdid 则将 cnnvd 的大部分信息插入
// 如果当前条目有对应的 cveid 且有对应的 cnvdid 则将cnvd 缺少的信息插入
func (m *Merge) mergeCnnvd() error {
	var maxId int64
	has, err := m.Engine.SQL("select max(id) from cnnvd_ins").Get(&maxId)
	if err != nil {
		return err
	}
	fmt.Println(maxId)
	if has {
		for id := 1; id <= int(maxId); id++ {
			cnnvd := new(types.CnnvdIns)
			_, err := m.Engine.ID(id).Get(cnnvd)
			if err != nil {
				continue
			}
			err = m.UpdateVeinmindVulnTableByCnnvd(*cnnvd)
			if err != nil {
				fmt.Println(err)
				continue
			}
		}
	}
	return nil
}

// 插入此条 cnnvd 的数据到 veinmind
func (m *Merge) insertCnnvd(cnnvd types.CnnvdIns) error {
	has, err := m.Engine.SQL("select * from veinmind_vulnerability where cnnvd_id = \"" + cnnvd.CnnvdId + "\"").Get()
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = m.Engine.Insert(cnnvd.ToVemindVulnerability())
	if err != nil {
		return err
	}
	return nil
}

// 根据 cveid 查询 veinmind 中对应的数据
func (m *Merge) findVeinmindVulnByCveId(id string) (vulns []types.VeinmindVulnerability, err error) {
	if id == "" {
		return vulns, err
	}
	err = m.Engine.SQL("select * from veinmind_vulnerability where cve_id = \"" + id + "\"").Find(&vulns)
	if err != nil {
		return vulns, err
	}
	fmt.Println(vulns)
	return vulns, nil
}

// 通过 cnnvd & veinmind 数据更新 veinmind 表
func (m *Merge) updateVeinmindVulnTableByCnnvd(vuln types.VeinmindVulnerability, cnnvd types.CnnvdIns) error {
	vuln.CnnvdId = cnnvd.CnnvdId
	vuln.VulnType = cnnvd.Type
	if vuln.CnvdId == "" {
		vuln.TitileZn = cnnvd.Name
		vuln.DescZn = cnnvd.Description
		vuln.FormalWay = cnnvd.Solution
		vuln.SeverityStr = cnnvd.Severity
	}
	_, err := m.Engine.ID(vuln.Id).Update(vuln)
	if err != nil {
		return err
	}
	return nil
}

// 通过 cnnvd 更新 veinmind 表
func (m *Merge) UpdateVeinmindVulnTableByCnnvd(cnnvd types.CnnvdIns) error {
	fmt.Println(cnnvd.OtherID)
	vulns, err := m.findVeinmindVulnByCveId(cnnvd.OtherID)
	if err != nil {
		return err
	}
	for _, vuln := range vulns {
		if vuln.CveId == "" {
			return m.insertCnnvd(cnnvd)
		}
		fmt.Println("a ..........")
		err = m.updateVeinmindVulnTableByCnnvd(vuln, cnnvd)
		if err != nil {
			fmt.Println(err)
			continue
		}
	}

	return nil
}
