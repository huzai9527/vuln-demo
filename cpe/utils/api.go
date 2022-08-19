package utils

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/xerrors"
)

func GetCpeList(cveId string) ([]string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 1000 * time.Millisecond}
	reqest, _ := http.NewRequest("GET", "https://127.0.0.1/api/cve/"+cveId, nil)
	reqest.Header.Set("Accept", "application/json")
	response, err := client.Do(reqest)
	if err != nil {
		return []string{}, xerrors.Errorf("get response from api :%s", err)
	}
	defer response.Body.Close()
	if response.StatusCode == 200 {
		cpelist, err := response2list(response.Body)
		if err != nil {
			return []string{}, xerrors.Errorf("parse response err: %s", err)
		}
		return cpelist, nil

	}

	return []string{}, xerrors.Errorf("get response from api statue :%s", err)

}

func response2list(body io.Reader) ([]string, error) {
	cpelist := []string{}
	data, _ := io.ReadAll(body)
	rst := gjson.Parse(string(data)).Get("vulnerable_product").Array()
	for _, s := range rst {
		cpelist = append(cpelist, s.String())
	}
	return cpelist, nil
}
