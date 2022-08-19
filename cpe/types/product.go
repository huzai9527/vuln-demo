package types

type ProductIns struct {
	Id          int64
	Platform    string `xorm:"varchar(55)"`
	SubPlatform string `xorm:"varchar(55)"`
	Name        string `xorm:"varchar(255)"`
	RawCpe      string `xorm:"varchar(255) index"`
}

