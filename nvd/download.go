package nvd

import (
	"github.com/aquasecurity/vuln-list-update/nvd"
)

type NvdObj struct {
}

func (o *NvdObj) Download(thisYear int) {
	nvd.Update(thisYear)
}
