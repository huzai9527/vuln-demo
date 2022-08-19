package main

import (
	"vuln-list-update/cpe"
)

func main() {
	// 测试nvd
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
	// 测试ubuntu
	// ubuntuobj := ubuntu.UbuntuObj{}
	// ubuntuobj.Download()
	//ubuntuobj.Store2Blot("./")
	// err := ubuntuobj.Stroe2Sql("root:asdqwe123.@tcp(localhost:3306)/vuln")
	// if err != nil {
	// 	panic(err)
	// }
	// 测试cnvd
	// cnvd := cnvd.Cnvdobj{}
	// err := cnvd.Download()
	// if err != nil {
	// 	panic(err)
	// }
	// err := cnvd.Store2Sql("root:asdqwe123.@tcp(localhost:3306)/vuln")
	// if err != nil {
	// 	panic(err)
	// }
	// 测试合并
	// mr := utils.Merge{}
	// err := mr.Init("root:asdqwe123.@tcp(localhost:3306)/vuln")
	// if err != nil {
	// 	panic(err)
	// }
	// err = mr.MergeAll()
	// if err != nil {
	// 	panic(err)
	// }
	// 测试从vuln-download的数据中获取并解压 cnnvd
	// err := utils.UnzipAllInDir("./cnnvd", "./")
	// if err != nil {
	// 	panic(err)
	// }

	// cnnvd := cnnvd.CnnvdObj{}
	// err := cnnvd.Store2Sql("root:asdqwe123.@tcp(localhost:3306)/vuln")
	// if err != nil {
	// 	panic(err)
	// }

	//测试 cve search api 使用
	// cpelist, err := cpeutils.GetCpeList("CVE-2012-3456")
	// if err != nil {
	// 	panic(err)
	// }
	// for _, cpe := range cpelist {
	// 	fmt.Println(cpe)
	// }
	// fmt.Println(cpelist)

	// 测试解析cpelist
	mysql := cpe.Mysql{}
	mysql.Init("root:asdqwe123.@tcp(localhost:3306)/vuln")
	err := mysql.Update()
	if err != nil {
		panic(err)
	}

}

//cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
//cpe:2.3:a:calligra:calligra:2.4:beta4:*:*:*:*:*:*
