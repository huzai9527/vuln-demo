package cnvd

import (
	"os/exec"
	"path"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	cnvdDir = "cnvd"
)

type Cnvdobj struct {
}

func (o *Cnvdobj) Download() error {
	dir := path.Join(utils.VulnListDir(), cnvdDir)
	args := []string{"./cnvd/download.py", "-o", dir}
	err := exec.Command("python3", args...).Run()
	if err != nil {
		return err
	}
	return nil
}
