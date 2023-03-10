package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const pub_1024 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtHMaK0Pq+04kv3hmjUdY
V7N1UACTTpqpC0bWSM/cClzrupB1JLsWfxHpab8T7rAS+sXdqcklH1zhnvgrtkWn
sCiEb5ONAfBrIy0raBaPHxKhFNtJOtveWmTcDGOfY6HcRrF+Smrexowih+TmVDs+
aFNYF2TjRSxukkW3HMqCb9sohx4csWnnBbt8PJE1vjUUPlKGBtaQTkpcHgqRFVPX
5ni/LQ2STYlBLM+fQuvebRvTjNO9U93TKp6LtjrQHh4ouKHWN9nDIKY483n7pOw3
tb2Ea5awTHiNg53WJnwwyWPNdWta6O1Z0otykrUU34jQs/CAbH6VtFjIP/vNGfsF
jwIDAQAB
-----END PUBLIC KEY-----`

const pri_1024 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0cxorQ+r7TiS/
eGaNR1hXs3VQAJNOmqkLRtZIz9wKXOu6kHUkuxZ/EelpvxPusBL6xd2pySUfXOGe
+Cu2RaewKIRvk40B8GsjLStoFo8fEqEU20k6295aZNwMY59jodxGsX5Kat7GjCKH
5OZUOz5oU1gXZONFLG6SRbccyoJv2yiHHhyxaecFu3w8kTW+NRQ+UoYG1pBOSlwe
CpEVU9fmeL8tDZJNiUEsz59C695tG9OM071T3dMqnou2OtAeHii4odY32cMgpjjz
efuk7De1vYRrlrBMeI2DndYmfDDJY811a1ro7VnSi3KStRTfiNCz8IBsfpW0WMg/
+80Z+wWPAgMBAAECggEAJLShJxnaq6HaocQJAEX592T+wPZNAJk/N5cCMa9ucAE0
xi9qVL1ltxVaqHMAx/Wy9qXXEBllXrrS/jY3Fg2XLaMgRV37OeDAulgO0057cHOm
popwm/NriHGpvS9qlaawGwUxzkts43BP+dqa65ldeXUynxebj0+ZclGSDN44qC3R
sdaDXyQRR8De7tAcEYHGvp3N6HhSvJ25ITWohJ2r+K548C56BbFvMfY43UnhfMgh
QTsskCeyrgchJg5Wp1oNdnaGVrMHwQEU9g6SuSDlDq4TIDDN6zoNyhFQbTA+6Hr0
71C+ShpB3UzhwJelDvj8ZLMrtPepVuREbMtv27A6KQKBgQDlVjRqp0xdxmvcZ3mI
N/cU4Dx3ktRoNxtljNyBPHdG0di9Neqw2KUSB8D/eHioLMzgoPlMOaY6Z46/nb5w
SYUEAkng1bjDwOGIH4WnBZUmIKdCkMOar3Y8x2d13lhItO9Ixgv6GH7icvIjhzgL
fG7crjBaarfxR9AC11IldKO8rQKBgQDJbdw/xFdUhLCberOSr3mK1YBWRLmt3MIL
7Ctl2ow/OqOgDdiKYqOupcACS1QlKqxuH4VzoYTfzOqse70YYXXjvMbmcFURgFwN
Yq7Hu6wi0OI4SVJwYxKyDjVx4bJWBj9MPbu3LLZdQ+6DWIFnDJvMn4oaNqK+zHtX
hqk4SH22qwKBgQCpydC0xXd8VdK1MsZ/Wy/KfNlHjaVEIshdvpPh+mo0PFhCfRBs
LXjIiIUSnpZ1q/ViuMrY7DVtOA4vPxIm/8dC2I7prlFEXCCdLvk8Vp29xJ8QYSzv
8MeQ5/BpC1xBN/OP5VAosMn/zSoHs6yClHVfXHbf+fKE563Q7KkcoeY3YQKBgB4R
dzpRndOxBwf+lgXEifkui7zU/36zoIfVFlla+WqK31gKGRP3S4XLmlD9W688oobB
z9MF/mbGGRXsVrrn+YgoauyFQj2dkqAw5fRM0JJV6h8K2vKJ54WK13GLhmqO/i3s
XTQnyYU8mcMjmBWA7VTrT9s/4qVmstbK9EHBmHqHAoGAHnSVyffqzQO4dF4r0KJ1
5NONYRl/nL3PJl8dI7q1xOrNQ4peoeOQkYi3WZ9jJS2pfm//F6yvn5X9bWq0nDFe
dmAgHGaKaPtdRvIDDTYHBFT9Cb56hJ8e+2DfSPHW3VjfMtxhs1KBNCo7cDezLHUM
5ZR/ozG5r+GjGRf/DfHONe8=
-----END PRIVATE KEY-----`

const user_pub = `-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1xsatShmgsXGJZcrmWLAUm3xQlJXr4E5vHcQZPZwEREWpmW1rsJdOeWAkz1hImXfrOXk1+f719nWIr3rjvPhgkPoOoYpXZSgHGgESnfVAO1PWwFtr9/5TpTwEM8c+ZBwJoEc5fGMrf/NkiLfoecdzx/5xWqF+Hd4SNbuqq1+03+Vlh2kyTHBwlb3wYl7mOPTSfQd1QriqIFI6CoVHydnl7qXs2iHeGG/eV/JRW5H5/pl5VXFfJR9hQjO+YE07zSQVi9HhV1UC+cvdfmIBRQ+Uqi6wFux5rtAQVIPAkk1WbMFOVkXfdc+eAtKsky65VouNb0oIbNmiicRPJCx3NtSyQIDAQAB-----END PUBLIC KEY-----`

func TestAddAsset(t *testing.T) {
	param := map[string]string{
		"server_ip":   "172.25.88.90",
		"is_expend":   "false",
		"server_type": "vm",
		"uni_mark":    "f79d7a05-bd1b-4471-b121-240ea7216527",
	}
	slated := getParamsVerify(param)
	param["verify"] = slated
	query := fmt.Sprintf("http://%s%s", "127.0.0.1:8080/", "api/v1/host")
	paramBody, err := json.Marshal(param)
	if err != nil {
		return
	}
	body := strings.NewReader(string(paramBody))
	resp, err := http.Post(query, "application/json", body)
	if err != nil {
		panic(err)
	}
	bytes, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("body: ", string(bytes))
}

func getParamsVerify(params map[string]string) string {
	var b []string
	str := ""
	for k := range params {
		b = append(b, k)
	}
	sort.Strings(b)
	for _, k := range b {
		str += fmt.Sprintf("\"%s\":\"%s\",", k, params[k])
	}
	str = fmt.Sprintf("{%s}", str[:len(str)-1])
	fmt.Println(str)
	h := md5.New()
	h.Write([]byte(str))
	h.Write([]byte("shunwang.com"))
	return hex.EncodeToString(h.Sum(nil))
}
func TestParams(t *testing.T) {
	a := []int{1, 2, 3}
	b, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}
	println(getParamsVerify(map[string]string{"a": "1", "b": strconv.FormatBool(true), "c": string(b)}))
}

type Model interface {
	createTable() string
}

type table1 struct {
	xx int
}

func (t table1) createTable() string {
	return ""
}

type table2 struct {
	xx int
}

func (t table2) createTable() string {
	return ""
}

type table3 struct {
	xx int
}

func (t table3) createTable() string {
	return ""
}

type ListNode struct {
	Value int
	Next  *ListNode
}

func Test_xxx(T *testing.T) {
	root := &ListNode{Value: 0, Next: nil}
	cacheNode := root
	for i := 1; i < 10; i++ {
		cacheNode.Next = &ListNode{
			Value: i, Next: nil,
		}
		cacheNode = cacheNode.Next
	}
	cur := root
	for cur != nil {
		T.Log(cur.Value)
		cur = cur.Next
	}
	reversalNode(root)
	println("")
	cur = root
	for cur != nil {
		T.Log(cur.Value)
		cur = cur.Next
	}
}

func reversalNode(node *ListNode) *ListNode {
	var (
		node1, node2, node3, result, cache *ListNode
	)
	cache = node
	node3 = node
	result = node
	for node3 != nil {
		node1 = cache
		if node1 == nil {
			return result
		}
		node2 = cache.Next
		if node2 != nil {
			node3 = node2.Next
			node1.Next = nil
			node2.Next = nil
			node2.Next = node1
			node1.Next = node3
			cache = node3
		}
	}
	return result
}

func TestSort(t *testing.T) {
	a := []int{5, 2, 8, 3, 1, 10}
	fmt.Printf("%v\n", a)
	sort.Ints(a)
	for _, v := range a {
		print(v)
	}
}

func TestTime(t *testing.T) {
	println(time.Now().UnixMilli())
}

func TestSign(t *testing.T) {
	signStr := "qwertyuikjhgfdsa"
	pri := initPri(pri_1024)
	pub := initPub(pub_1024)
	a, err := RSASign(pri, signStr)
	if err != nil {
		println(err.Error())
		return
	}
	println(a)
	println(RSAVerifySign(pub, a, signStr) != nil)
	q := "KBlRptBhdgHiHoslYFkunSeNyaq3UZtV2XPLbYeEvVgaEfPwcLj6LWkD9TTsvW3fr+2mNwz3wXkd8ZauodvEvT8XCzuWcmDnjJH0VzvRRsGa+Tvsxp/3RD0oDa8BfSBW6eFnNsyYeKSIKBtGLgrisFgXjj6yw1aFq+bx8djy9LgaaaRNnOeBoxJCZvTxRR0hVW+3hv6NbEVH6KTQRyVEkm+FtPU4Tz+Tlzxx7LBIAjrewFFZz5DAmiP5EPthDmybxWkQ+/uYEGGn/MXPbcl0CTIc1ted3CGE9RSsmA+4BuaAJZvs/0RrPW/+aonEJJICSpl/FXJzm4wtQUeds+WVRA=="
	println(RSAVerifySign(pub, q, signStr) != nil)
}

func TestUserSign(t *testing.T) {
	signStr := "q1+03+Vlh2k"
	pub := initPub(user_pub)
	a := "AYLbe1Wa/ZzrwR5PBpsb5dVGGPy7fY/LNzh6fVE/QyJrqYivmjFLGe3ZUAd/7zrDCc38Pj11qa76nhnVlkxhL18fskkZI051E9txLoAvdNwemL1/SiJBl7Hdzr37F/r/B18CfqmbuCernVh5BS3BOpPPNqqmxmlcX/xd43r6Zkm98C588PgAbbXr7Vaqcd0b3Nx30RgpIfDvSTBFt9SvehUBfzufGNn6+Z7KyhAYoP3lY6y1f4Bmmk/B0xfyacN8HgudiQEjqrwTM5Bk8prKq56D+wrQepD2pvyNP/95BrxCyP/uI+z08mk2JVq9wUJAcs5xs9ACl7UJmrhdnLpamg=="
	println(RSAVerifySign(pub, a, signStr) != nil)
}
