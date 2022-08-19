package cnnvd

import (
	"path"
)

const (
	cnnvdDir = "cnnvd"
)

type CnnvdObj struct {
}

func (o *CnnvdObj) Store2Sql(dsn string) error {
	mysql := Mysql{}
	if err := mysql.Init(dsn); err != nil {
		return err
	}
	Vulndir := path.Join("./vuln-list", cnnvdDir)
	if err := mysql.Update(Vulndir); err != nil {
		return err
	}

	return nil
}
