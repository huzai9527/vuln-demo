package nvd

import (
	"path"

	"github.com/aquasecurity/vuln-list-update/utils"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/nvd"
)

func (o *NvdObj) Store2Blot(dir string) error {
	db.Init(dir)
	vs := nvd.NewVulnSrc()
	vulnDir := path.Join(utils.VulnListDir(), nvdDir)
	vs.Update(vulnDir)
	return nil
}

func (o NvdObj) Stroe2Sql(dsn string) error {
	mysql := Mysql{}
	if err := mysql.Init(dsn); err != nil {
		return err
	}
	Vulndir := path.Join(utils.VulnListDir(), nvdDir)
	mysql.Update(Vulndir)
	return nil
}
