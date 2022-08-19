package cnvd

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"vuln-list-update/types"

	"github.com/aquasecurity/trivy-db/pkg/utils"
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
	if err := engine.DropTables(new(types.CnvdIns)); err != nil {
		return err
	}
	if err := engine.Sync2(new(types.CnvdIns)); err != nil {
		return err
	}
	m.Engine = engine
	return nil
}

func (m *Mysql) Update(dir string) error {
	var items []types.CNVDList
	buffer := &bytes.Buffer{}
	err := utils.FileWalk(dir, func(r io.Reader, _ string) error {
		item := types.CNVDList{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return xerrors.Errorf("failed to read file: %w", err)
		}
		if err := xml.Unmarshal(buffer.Bytes(), &item); err != nil {
			return xerrors.Errorf("failed to decode CNVD XML: %w", err)
		}
		buffer.Reset()
		items = append(items, item)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in CNVD walk: %w", err)
	}

	if err = m.commit(items); err != nil {
		return xerrors.Errorf("error in CNVD save: %w", err)
	}

	return nil
}

func (m *Mysql) commit(items []types.CNVDList) error {
	fmt.Println("len -> ", len(items))
	for _, item := range items {
		fmt.Println(item)
		for _, cnvd := range item.CNVD {
			_, err := m.Engine.Insert(cnvd.ToCnvdIns())
			if err != nil {
				return xerrors.Errorf("error in insert cnvd to mysql: %w", err)
			}
		}
	}
	return nil
}
