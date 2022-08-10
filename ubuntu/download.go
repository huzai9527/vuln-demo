package ubuntu

import (
	"github.com/aquasecurity/vuln-list-update/ubuntu"
)

type UbuntuObj struct {
}

func (o *UbuntuObj) Download() {
	ubuntu.Update()
}
