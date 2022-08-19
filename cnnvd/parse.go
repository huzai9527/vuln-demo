package cnnvd

import (
	"bufio"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
	"vuln-list-update/types"

	xmlparser "github.com/tamerh/xml-stream-parser"
)

func escapeInvalidUTF8Byte(input string) string {
	// 将非法的 utf8 序列中的字符转换为 `\x` 的模式
	// 注意，这个操作返回的结果和原始字符串是非等价的
	// 详见测试 TestEscapeInvalidUTF8Byte
	s := []byte(input)
	ret := make([]rune, 0, len(s)+20)
	start := 0
	for {
		r, size := utf8.DecodeRune(s[start:])
		if r == utf8.RuneError {
			// 说明是空的
			if size == 0 {
				break
			} else {
				// 不是 rune
				ret = append(ret, []rune(fmt.Sprintf("\\x%02x", s[start]))...)
			}
		} else {
			// 不是换行之类的控制字符
			if unicode.IsControl(r) && !unicode.IsSpace(r) {
				ret = append(ret, []rune(fmt.Sprintf("\\x%02x", r))...)
			} else {
				// 正常字符
				ret = append(ret, r)
			}
		}
		start += size
	}
	return string(ret)
}

func tryGetText(e []xmlparser.XMLElement) string {
	if len(e) > 0 {
		return escapeInvalidUTF8Byte(e[0].InnerText)
	} else {
		return ""
	}
}

func Parse(f io.Reader) (types.CNNVDList, error) {
	data := types.CNNVDList{}
	br := bufio.NewReaderSize(f, 10240000)
	parser := xmlparser.NewXMLParser(br, "entry").SkipElements([]string{"vulnerable-configuration", "vuln-software-list"})
	for item := range parser.Stream() {
		e := types.CNNVDEntry{
			Name:        tryGetText(item.Childs["name"]),
			CnnvdId:     tryGetText(item.Childs["vuln-id"]),
			Published:   tryGetText(item.Childs["published"]),
			Modified:    tryGetText(item.Childs["modified"]),
			Severity:    tryGetText(item.Childs["severity"]),
			Type:        tryGetText(item.Childs["vuln-type"]),
			Description: tryGetText(item.Childs["vuln-descript"]),
			Solution:    tryGetText(item.Childs["vuln-solution"]),
		}
		if len(item.Childs["other-id"]) > 0 && len(item.Childs["other-id"][0].Childs["cve-id"]) > 0 {
			e.OtherID.CVE = escapeInvalidUTF8Byte(item.Childs["other-id"][0].Childs["cve-id"][0].InnerText)
		}
		data.CNNVD = append(data.CNNVD, e)
	}
	return data, nil
}
