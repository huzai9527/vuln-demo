package types

var PartNameMapping = map[string]string{
	"o": "操作系统",
	"a": "应用",
	"h": "硬件",
}

type VersionTmp map[string][]string
type ProductTmp map[string]VulnerableProduct
type VulnerableProduct struct {
	Part       string
	Vender     string
	Product    string
	RawCpe     string
	VersionSet []string
}

func (v *VulnerableProduct) ToProductIns() ProductIns {
	return ProductIns{
		Platform:    PartNameMapping[v.Part],
		SubPlatform: v.Vender,
		Name:        v.Product,
		RawCpe:      v.RawCpe,
	}
}
func (v *VulnerableProduct) ToProduct2VulnIns() Product2Vuln {
	return Product2Vuln{
		AffectedVersionSet: v.VersionSet,
	}
}
