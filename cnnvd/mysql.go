package cnnvd

import (
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

func (m *Mysql) Init(dsn string) error {
	engine, err := xorm.NewEngine("mysql", dsn)
	if err != nil {
		return err
	}
	// 这里应该在最开始的时候删除，中间过程中不可以删除
	// 否则会丢失数据，这里目前只有nvd，方便调试
	if err := engine.DropTables(new(types.CnnvdIns)); err != nil {
		return err
	}
	if err := engine.Sync2(new(types.CnnvdIns)); err != nil {
		return err
	}
	m.Engine = engine
	return nil
}

func (m *Mysql) Update(dir string) error {
	var items []types.CNNVDList
	err := utils.FileWalk(dir, func(r io.Reader, _ string) error {
		item, err := Parse(r)
		fmt.Println(item.CNNVD)
		if err != nil {
			return err
		}
		items = append(items, item)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in CNVD walk: %w", err)
	}
	fmt.Println(items)
	if err = m.commit(items); err != nil {
		return xerrors.Errorf("error in CNVD save: %w", err)
	}

	return nil
}

func (m *Mysql) commit(items []types.CNNVDList) error {
	fmt.Println("len -> ", len(items))
	for _, item := range items {
		fmt.Println(item)
		for _, cnnvdEntry := range item.CNNVD {
			_, err := m.Engine.Insert(cnnvdEntry.ToCnnvdIns())
			if err != nil {
				return xerrors.Errorf("error in insert cnvd to mysql: %w", err)
			}
		}
	}
	return nil
}
