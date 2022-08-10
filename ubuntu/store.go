package ubuntu

import (
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/vuln-list-update/utils"
)

func (o *UbuntuObj) Store2Blot(dir string) {
	db.Init(dir)
	vs := ubuntu.NewVulnSrc()
	vs.Update(utils.CacheDir())
}

func (o *UbuntuObj) Stroe2Sql(dsn string) error {
	mysql := Mysql{}
	if err := mysql.Init(dsn); err != nil {
		return err
	}
	mysql.Update(utils.CacheDir())
	return nil
}
