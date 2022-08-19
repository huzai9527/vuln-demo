package cnvd

import (
	"path"

	"github.com/aquasecurity/vuln-list-update/utils"
)

func (o *Cnvdobj) Store2Sql(dsn string) error {
	mysql := Mysql{}
	if err := mysql.Init(dsn); err != nil {
		return err
	}
	Vulndir := path.Join(utils.VulnListDir(), cnvdDir)
	if err := mysql.Update(Vulndir); err != nil {
		return err
	}

	return nil
}
