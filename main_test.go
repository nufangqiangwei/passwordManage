package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
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
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueCsckXrWhnTk9WsHo7l
dlfoA0OMRRjp6/Gyu39G/Lbln3jsYwDhhW0b4t+xyUABH9DQX+LTb023y0OWqKtP
iJguyd+PqE2Zzqo4iDfJmd6zj6x6ScMJmVhZtiNVJ2unQXj5p6iVPhnBQi95NtY8
ODhvpyEIifUM5d7v2Y/VQEoqv4BE548XPqpTci0qGHXkSgW30WyOpQJoQO6XbhFS
5fCNKZgioJy6ECu6WIk8FHa12RsA5rXbdDlE4Ru32kO+V283svtd4tBW7sZsEq3b
DmwtgVk3DL7kwhSn3EmbtwDHLrbiRESUb8MzXKml7GPNSLHhAOEcATSjGjzlhO41
QQIDAQAB
-----END PUBLIC KEY-----`

const pri_1024 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC54KxyRetaGdOT
1awejuV2V+gDQ4xFGOnr8bK7f0b8tuWfeOxjAOGFbRvi37HJQAEf0NBf4tNvTbfL
Q5aoq0+ImC7J34+oTZnOqjiIN8mZ3rOPrHpJwwmZWFm2I1Una6dBePmnqJU+GcFC
L3k21jw4OG+nIQiJ9Qzl3u/Zj9VASiq/gETnjxc+qlNyLSoYdeRKBbfRbI6lAmhA
7pduEVLl8I0pmCKgnLoQK7pYiTwUdrXZGwDmtdt0OUThG7faQ75Xbzey+13i0Fbu
xmwSrdsObC2BWTcMvuTCFKfcSZu3AMcutuJERJRvwzNcqaXsY81IseEA4RwBNKMa
POWE7jVBAgMBAAECggEBAJCVC24DpvK5vhJzFOPcIO5xqD3Jr/UbUPE/WthvQydV
mLz30V+dEs63NQa/G0pAZ994jGzZQb+FA16vXyQpxL6qKVLLe7HdUrMnQrvqMP1n
9eHetmxjsja+O2Hqj9UO7tWFpSPdhOD+JY424SFfeQ3+EBM/JaYxn2u6gnSHZcgP
09cM6OOG6KzUjYNwZ5mU0hBr0aUlZ3eerxXcw/FmLl3FPp6+kQ3sRjj03DPvUk1J
Vf+YEnlnCws8R5fCWfxthDURPL3xqlChpFSKzDLhtyempsBNXmrEEG2aEkWQDxZW
gN4ceTz2VZ0BOO8k9cfs7NyaVzH9tDn5IfTRAh7GZ9UCgYEA7920T+4r4tQmU15H
Vqdl2JxZjHsDdDY/bUltLtijYIEwDQGbmxyaLY0bzLoGO1zTmHKFtiTS1M+eoeS9
pxd8YcZddsmGVzH+ugvEe7momgQLyGEBqZbZuWppPoA0P7Tb171n41jmwe+dlkWd
WCzUw58zBHp+wwnUbtyz2X6JGZMCgYEAxmFVXFZRe0aohxX2UAOouO1BSyBMtN17
rmfXLEziBMD3LUKciYrDQep44nEH8MzKhmsgqzHtXmdheoOsCpcPkqtd3bOQvEuR
adVeFiTajtPXCOUVU1Yx2Oj8KKy/hGwjUoBAgDr9jNIE86FPj+B6hPn+wm37v+Qm
d8t72EQAKlsCgYAzy+RL/lpruPQtvIYbKDrN87VCqK2uQqifqONy4kUlacA+jsJT
VHHWtEn0g5ck6n6mxNQq6Pi+C7dtrj9l/aRWWMeGBy6DVcBz3GapcQX/fDAvLQN2
46RQbbIcVQLzXtK6W6Q7a88owd19vbqkd8naFF6n8Ou+ojjFV9Nee/yPEQKBgD+z
OWmw/fELu0nFL5Z51k+rP3AUKw1YoUJbbah394t3Oud5oDI6MICV/cMYcGhOGioX
dCIEoifSImboqPGtl/6MsFNkOXF9AnBtZwzNQLDkLQRaKwLbhp4UEgQtlEG9R4pS
TGPgjVIOjjB898NHXZAdhkSAdHollISa/mVvUG5JAoGAKSEYpn1eILMSESKjJXi0
xvaThRnJzRSHM4OmFRsyrY/crts0JYHCt5tAAm+6CdB+CYGgB31tcd1ixBJ3SU6W
9h+FuP7qtQ5kQ9S7j5LxzJSK5yb5WkFFLT/j4BuVoI+0sxxkgoA8dmb2cNURRPK+
VrhAegWp3ToX4IqUcw8cyWs=
-----END PRIVATE KEY-----`

const user_pub = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6+BLTc0Xez1mczTNZIxl
my8byyHQiVPIebQTA1R07gypj6+W67T7VVeuTnH6VeuttMT3cqido9KIGJAv9g5m
YnJnhcBaR1a/LSpwDxxCXNd7u5fGTnSt4qKqk4vCOPcLFA/3QO6KlLkTARh9+YI6
6SGymi+RF2XrrePnrzlVqNmEAsJAAOAbIOEeNmje7Ku4LBcPM1cNEAf1ZNsuN0NL
Stwa5IqQomJnXLlANm2fLs6g6X2ZBApdaXn8oHVValiIi5FlDgzKrTVpVA6g9ghO
NJSSuEnHeI8CfexPX2b2pcokLSx+EgfxZlPQnSZ8UKah4YGsTPHmvu7wnsuY0oFZ
IwIDAQAB
-----END PUBLIC KEY-----`

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
	signStr := "JJDdjIJRq2"
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
	signStr := "JJDdjIJRq2"
	pub := initPub(user_pub)
	a := "RHE68MupKBd7tqqiO83IxsvQWZBzEQk8MHNZ69RTcmObkxPfTp0vBDbhgMzZSxnUvbNbDzgXo65BEKYddgcm2+0A1j2thipYQxlhz11iv8vXnt9RUrHkjCPIa3e4inAjn2umrDliM81vDWu0Vju8b4mqd9w0SrojrmlEHpfXgv86bS4jzGDV+3T6vDtxBbpgvC3rvKzryYwjqRnlw1vAOstQebpFnxj1NXMdQTXJyxDaPT8MaCwfdGXq/hriMfPwTGaoTGVQpxlNAJhCOzt7L44OeyT/8eLpFf5psDKDa6zGfjjpWZmhkse059lN/j+EGc9ClMbJ2uTYcBVio8VE5A=="
	println(RSAVerifySign(pub, a, signStr) != nil)
}

func TestBase64Str(t *testing.T) {
	str := []byte{
		0, 13, 14, 19, 4, 67, 20,
	}
	println(base64.StdEncoding.EncodeToString(str))
	signStr := "JJDdjIJRq2"
	a := []byte(signStr)
	fmt.Printf("%v\n", a)
	hashMD5 := md5.New()
	hashMD5.Write(a)
	Digest := hashMD5.Sum(nil)
	fmt.Printf("%v\n", Digest)
	r := []rune(signStr)
	fmt.Printf("%v\n", r)
}

func TestRSAEncryption(t *testing.T) {
	dataStr := "JJDdjIJRq2"
	dataStrHash := []byte{198, 58, 7, 70, 190, 170, 40, 178, 60, 142, 131, 255, 36, 187, 67, 55, 115, 112, 225, 104, 214, 208, 167, 249, 43, 171, 235, 209, 193, 26, 39, 18}
	hashSHA256 := sha256.New()
	hashSHA256.Write([]byte(dataStr))
	Digest := hashSHA256.Sum(nil)
	fmt.Printf("%v\n", Digest)
	fmt.Printf("%v\n", dataStrHash)
	pri := initPri(pri_1024)
	a, err := RSASign(pri, dataStr)
	if err != nil {
		println(err.Error())

	}
	println(a)
}
