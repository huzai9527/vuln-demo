package main

import (
	"vuln-list-update/ubuntu"
)

func main() {
	// nvdobj := nvd.NvdObj{}
	// start to download nvd source
	// nvdobj.Download(2022)
	// store nvdsrc to blot
	// nvdobj.Store()
	// store nvdsrc to mysql
	// err := nvdobj.Stroe2Sql("root:asdqwe123.@tcp(localhost:3306)/vuln")
	// if err != nil {
	// 	panic(err)
	// }

	ubuntuobj := ubuntu.UbuntuObj{}
	// ubuntuobj.Download()
	//ubuntuobj.Store2Blot("./")
	err := ubuntuobj.Stroe2Sql("root:asdqwe123.@tcp(localhost:3306)/vuln")
	if err != nil {
		panic(err)
	}
}
