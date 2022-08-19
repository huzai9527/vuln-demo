package cpe

import (
	"bytes"
	"strings"
	cpetypes "vuln-list-update/cpe/types"
	cpeutils "vuln-list-update/cpe/utils"

	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"golang.org/x/xerrors"
)

const Seprator = "::"

func GetVulnerableProductFromCveId(cveId string) ([]cpetypes.VulnerableProduct, error) {
	cpelist, err := cpeutils.GetCpeList(cveId)
	if err != nil {
		return nil, xerrors.Errorf("get cpelist err: %s", err)
	}
	tmp := cpetypes.VersionTmp{}
	for _, cpe := range cpelist {
		wfn, err := getWellFormedCpe(cpe)
		if err != nil {
			log.Logger.Errorf("get wellformedname err :%s", err)
			continue
		}
		rawCpe := wfn.GetString("part") + Seprator + wfn.GetString("vendor") + Seprator + wfn.GetString("product")
		version := wfn.GetString("version") + Seprator + wfn.GetString("update") + Seprator + wfn.GetString("edition")
		tmp[rawCpe] = append(tmp[rawCpe], delx(version))
	}
	rst := []cpetypes.VulnerableProduct{}
	for k, v := range tmp {
		rawCpe := strings.Split(k, Seprator)
		part := rawCpe[0]
		vender := rawCpe[1]
		product := rawCpe[2]
		vulnProduct := cpetypes.VulnerableProduct{
			Part:       part,
			Vender:     vender,
			Product:    product,
			RawCpe:     k,
			VersionSet: v,
		}
		rst = append(rst, vulnProduct)
	}
	return rst, nil
}

func getWellFormedCpe(cpe string) (rst common.WellFormedName, err error) {
	rst, err = naming.UnbindFS(cpe)
	if err != nil {
		return nil, xerrors.Errorf("parse cpe err: %s", err)
	}
	return rst, nil
}

func delx(str string) string {
	var buf bytes.Buffer
	for _, c := range str {
		if c == '\\' {
			continue
		}

		buf.WriteRune(c)
	}

	return buf.String()
}
