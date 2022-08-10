package nvd

import (
	"github.com/aquasecurity/vuln-list-update/utils"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/nvd"
)

func (o *NvdObj) Store2Blot(dir string) error {
	db.Init(dir)
	vs := nvd.NewVulnSrc()
	vulnListPath := utils.CacheDir()
	vs.Update(vulnListPath)
	return nil
}

func (o NvdObj) Stroe2Sql(dsn string) error {
	mysql := Mysql{}
	if err := mysql.Init(dsn); err != nil {
		return err
	}
	vulnListPath := utils.CacheDir()
	mysql.Update(vulnListPath)
	return nil
}
