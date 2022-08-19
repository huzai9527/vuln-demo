package cpe

import (
	cpetypes "vuln-list-update/cpe/types"
	"vuln-list-update/types"

	"github.com/aquasecurity/trivy-db/pkg/log"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/xerrors"
	"xorm.io/xorm"
)

type Mysql struct {
	Engine *xorm.Engine
}

func (m *Mysql) Init(dsn string) (err error) {
	engine, err := xorm.NewEngine("mysql", dsn)
	if err != nil {
		return err
	}
	// 这里应该在最开始的时候删除，中间过程中不可以删除
	// 否则会丢失数据，这里目前只有nvd，方便调试
	if err := engine.DropTables(new(cpetypes.ProductIns), new(cpetypes.Product2Vuln)); err != nil {
		return err
	}
	if err := engine.Sync2(new(cpetypes.ProductIns), new(cpetypes.Product2Vuln), new(types.VeinmindVulnerability)); err != nil {
		return err
	}
	m.Engine = engine
	return nil
}
func (m *Mysql) Update() error {
	var maxId int64
	has, err := m.Engine.SQL("select max(id) from vulnerability_detail").Get(&maxId)
	if err != nil {
		return err
	}
	if has {
		var vulnid int64
		for vulnid = 1; vulnid <= maxId; vulnid++ {
			vuln := new(types.VulnerabilityDetail)
			m.Engine.ID(vulnid).Get(vuln)
			vulnProducts, err := GetVulnerableProductFromCveId(vuln.CveId)
			if err != nil {
				log.Logger.Errorf("get vulnProducts err:%s", err)
			}
			for _, vulnproduct := range vulnProducts {
				err := m.insertProduct(vulnproduct)
				if err != nil {
					log.Logger.Errorf("insert product err :%s", err)
					continue
				}
				productId, err := m.getProductIdfromRawCpe(vulnproduct.RawCpe)
				if err != nil {
					log.Logger.Error(err)
				}
				err = m.insertProduct2Vuln(vulnproduct, vulnid, productId)
				if err != nil {
					log.Logger.Error(err)
				}
			}

		}
	}
	return nil
}

func (m *Mysql) isProductExistByRawCpe(rawCpe string) (bool, error) {
	return m.Engine.SQL("select * from product_ins where raw_cpe = ?", rawCpe).Exist()
}

func (m *Mysql) insertProduct(product cpetypes.VulnerableProduct) error {
	has, err := m.isProductExistByRawCpe(product.RawCpe)
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = m.Engine.Insert(product.ToProductIns())
	if err != nil {
		return xerrors.Errorf("insert product err: %s", err)
	}
	return nil
}

func (m *Mysql) getProductIdfromRawCpe(rawCpe string) (int64, error) {
	product := cpetypes.ProductIns{}
	has, err := m.Engine.SQL("select * from product_ins where raw_cpe = ?", rawCpe).Get(&product)
	if err != nil {
		return 0, xerrors.Errorf("get product id err :%s", err)
	}
	if has {
		return product.Id, nil
	}
	return 0, xerrors.New("does not find the product")

}

func (m *Mysql) insertProduct2Vuln(product cpetypes.VulnerableProduct, vulnId int64, productId int64) error {
	product2vuln := cpetypes.Product2Vuln{
		ProductId:          productId,
		VulnId:             vulnId,
		AffectedVersionSet: product.VersionSet,
	}
	_, err := m.Engine.Insert(product2vuln)
	if err != nil {
		return xerrors.Errorf("insert product2vuln err :%s", err)
	}
	return err
}
