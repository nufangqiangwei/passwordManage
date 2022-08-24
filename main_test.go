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
)

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

func TestRSA(t *testing.T) {
	var sysConfig interface{}
	sysConfig = &User{}
	_, ok := sysConfig.(*User)
	if !ok {
		println("错误")
		return
	}
	println("正确")
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

func TestVersion(t *testing.T) {
	versionList := getUserPasswordVersion(2)
	var lastVersion int
	if len(versionList) == 0 {
		lastVersion = 1
	} else {
		lastVersion = versionList[len(versionList)-1] + 1
	}
	fmt.Printf("%v\n", versionList)
	println(lastVersion)
}
