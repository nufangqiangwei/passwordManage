package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var db *sql.DB

func checkUserFunc(ctx *gin.Context) {
	jsonParams := make(map[string]interface{})

	err := ctx.BindJSON(&jsonParams)
	if err != nil {
		fmt.Printf("%+v", err)
		ctx.JSON(http.StatusBadRequest, ErrResponse{Code: 404, Message: "参数错误"})
		return
	}
	UserId, _ := jsonParams["UserId"].(string)
	EncryptStr, _ := jsonParams["EncryptStr"].(string)
	TimestampStr, _ := jsonParams["Timestamp"].(string)
	Timestamp, err := strconv.Atoi(TimestampStr)
	if err != nil {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 400, Message: "参数错误"})
		ctx.Abort()
		return
	}
	if time.Now().Unix()-int64(Timestamp) > 60 {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 500, Message: "参数错误"})
		ctx.Abort()
		return
	}
	if UserId == "" || EncryptStr == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 400, Message: "缺少参数"})
		ctx.Abort()
		return
	}
	user := &User{}
	queryOneUser(user, "select * from user where Id=?", UserId)
	if user.usermd5 == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "用户错误"})
		ctx.Abort()
		return
	}
	sysConfig := &SysConfig{}
	queryOneSysConfig(sysConfig, "select * from sysconfig where configkey=?", "webPriKey")
	if sysConfig.ConfigValue == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "系统没有添加私钥"})
		ctx.Abort()
		return
	}
	enn, err := base64.StdEncoding.DecodeString(EncryptStr)
	if err != nil {
		panic(err)
	}
	encryptStr, err := DecrptogRSA(enn, initPri(sysConfig.ConfigValue))
	if err != nil {
		println(err)
		ctx.JSON(http.StatusOK, ErrResponse{Code: 413, Message: "密钥错误"})
		ctx.Abort()
		return
	}
	if string(encryptStr) != user.encryptStr+TimestampStr {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 400, Message: "密钥错误"})
		ctx.Abort()
		return
	}
	//ctx.Keys = make(map[string]interface{})
	//ctx.Keys["user"] = user
	ctx.Set("user", user)
	bodyParams, err := json.Marshal(jsonParams)
	if err != nil {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 500, Message: "写入错误"})
		ctx.Abort()
		return
	}
	ctx.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyParams))
}

type ErrResponse struct {
	Code    int
	Message string
}
type registerResponse struct {
	Code       int
	UserId     int64
	WebPubKey  string
	EncryptStr string
}
type Response struct {
	Code    int
	Message string
	Data    []interface{}
}

// request Model
type registerForm struct {
	UserPubKey string `from:"UserPubKey" binding:"required"`
	EncryptStr string `from:"EncryptStr" binding:"required"`
}
type UserDataForm struct {
	WebKey  string `json:"webKey"`
	WebData string `json:"fromData"`
}
type saveUserDataForm struct {
	EncryptStr string         `json:"EncryptStr"`
	Timestamp  string         `json:"Timestamp"`
	UserId     string         `json:"UserId"`
	UserData   []UserDataForm `json:"UserData"`
}
type WebListForm struct {
	Name   string `from:"Name" binding:"required"`
	WebKey string `from:"WebKey" binding:"required"`
	Icon   string `from:"Icon"`
}

// model
type User struct {
	id         int64
	encryptStr string
	userPubKey string
	usermd5    string
}
type SysConfig struct {
	ConfigKey   string
	ConfigValue string
}
type WebList struct {
	Id     int64
	Name   string
	WebKey string
	Icon   string
}
type UserData struct {
	id        int64
	userId    int64
	webKey    string
	webData   string
	timeStamp int64
	delete    bool
}

func init() {
	db, _ = sql.Open("mysql", "qiangwei:Qiangwei@tcp(101.32.15.231:6603)/mypassword")
}
func main() {
	app := gin.Default()
	app.POST("/register", registerView)
	app.GET("/webList", getWebListView)

	checkUser := app.Use(checkUserFunc)
	{
		checkUser.POST("/SaveUserData", saveUserDataView)
		checkUser.POST("/GetUserData", getUserDataView)
		checkUser.POST("/AppendWebAddress", AppendWebListView)
	}
	app.Run(":8080")

}

func registerView(ctx *gin.Context) {
	var form registerForm

	if ctx.ShouldBind(&form) != nil {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "参数错误"})
		return
	}
	h := md5.New()
	h.Write([]byte(form.UserPubKey))
	userMd5 := hex.EncodeToString(h.Sum(nil))
	var user User
	queryOneUser(&user, "select * from user where usermd5=?", userMd5)
	sysConfig := &SysConfig{}
	queryOneSysConfig(sysConfig, "select * from sysconfig where configkey=?", "webPriKey")
	if sysConfig.ConfigValue == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "系统没有添加私钥"})
		return
	}
	if user.usermd5 != "" {
		ctx.JSON(http.StatusOK, registerResponse{Code: 200, UserId: user.id, WebPubKey: sysConfig.ConfigValue, EncryptStr: user.encryptStr})
		return
	}
	user.usermd5 = userMd5
	user.encryptStr = form.EncryptStr
	user.userPubKey = form.UserPubKey
	saveUser(&user)
	ctx.JSON(http.StatusOK, registerResponse{Code: 200, UserId: user.id, WebPubKey: sysConfig.ConfigValue, EncryptStr: user.encryptStr})

}
func getWebListView(ctx *gin.Context) {
	var queryWebList []WebList
	queryAllWebList(&queryWebList)
	ctx.JSON(http.StatusOK, map[string]interface{}{"code": 200, "message": "ok", "Data": queryWebList})
}
func saveUserDataView(ctx *gin.Context) {
	var (
		webKeyList        []string
		user              *User
		queryUserDataList []UserData
		saveUserDtaList   []UserData
		timeStamp         int64
		form              saveUserDataForm
	)
	binerr := ctx.BindJSON(&form)
	if binerr != nil {
		println(binerr.Error())
		ctx.JSON(http.StatusOK, ErrResponse{Code: 403, Message: "参数错误"})
		return
	}

	for _, value := range form.UserData {
		webKeyList = append(webKeyList, value.WebKey)
	}

	data, exist := ctx.Get("user")
	if !exist {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 500, Message: "写入错误"})
		return
	}

	user, ok := data.(*User)
	if !ok {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 500, Message: "内部错误"})
		return
	}
	println("准备查询数据")
	// todo 不能传入切片，需要拼接字符串
	queryUserData(&queryUserDataList, "select * from user_data where user_id=? and web_key=?", user.id, webKeyList)
	println("查询数据成功")
	deletedUserData(queryUserDataList)
	println("更新数据")
	timeStamp = time.Now().Unix()
	for _, value := range form.UserData {
		saveUserDtaList = append(saveUserDtaList, UserData{
			userId:    user.id,
			webKey:    value.WebKey,
			webData:   value.WebData,
			timeStamp: timeStamp,
		})
	}
	saveUserData(saveUserDtaList)
}
func getUserDataView(ctx *gin.Context) {
	var queryUserDataList []UserData
	lastPushTime := ctx.Request.PostFormValue("lastPushTime")
	user, ok := ctx.Keys["user"].(User)
	if !ok {
		panic("")
	}

	if lastPushTime == "" {
		queryUserData(&queryUserDataList, "select * from user_data where user_id=?", user.id)
	} else {
		queryUserData(&queryUserDataList, "select * from user_data where user_id=? and time_stamp=?", user.id, lastPushTime)
	}

	var result map[string]string
	for _, value := range queryUserDataList {
		result[value.webKey] = value.webData
	}
	ctx.JSON(http.StatusOK, map[string]interface{}{"Code": 200, "Message": "ok", "Data": result})
}
func AppendWebListView(ctx *gin.Context) {
	var form WebListForm

	if ctx.ShouldBind(&form) != nil {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "参数错误"})
		return
	}
	var weblist WebList
	queryOneWebList(&weblist, "select * from weblist where WebKey=?", form.WebKey)
	if weblist.Id != 0 {
		ctx.JSON(http.StatusOK, map[string]interface{}{"Code": 400, "Message": "该网站已添加"})
	}
	weblist.Name = form.Name
	weblist.WebKey = form.WebKey
	weblist.Icon = form.Icon
	saveWebList(&weblist)
	ctx.JSON(http.StatusOK, map[string]interface{}{"Code": 200, "Message": "ok"})
}

func queryOneSysConfig(sysConfig *SysConfig, querySql string, args ...interface{}) {
	err := db.QueryRow(querySql, args...).Scan(&sysConfig.ConfigKey, &sysConfig.ConfigValue)
	if err != nil {
		panic(err)
	}
}
func queryOneUser(user *User, querySql string, args ...interface{}) {
	err := db.QueryRow(querySql, args...).Scan(&user.id, &user.encryptStr, &user.userPubKey, &user.usermd5)
	if err != nil {
		return
	}
}
func queryOneWebList(weblist *WebList, querySql string, args ...interface{}) {
	err := db.QueryRow(querySql, args...).Scan(&weblist.Id, &weblist.Name, &weblist.WebKey, &weblist.Icon)
	if err != nil {
		panic(err)
	}
}
func querySysConfig(sysConfigList *[]SysConfig, querySql string, args ...interface{}) {
	rows, err := db.Query(querySql, args...)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		sysConfig := SysConfig{}
		rows.Scan(&sysConfig.ConfigKey, &sysConfig.ConfigValue)
		*sysConfigList = append(*sysConfigList, sysConfig)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

}
func queryUser(userList *[]User, querySql string, args ...interface{}) {
	rows, err := db.Query(querySql, args...)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		user := User{}
		rows.Scan(&user.id, &user.encryptStr, &user.userPubKey, &user.usermd5)
		*userList = append(*userList, user)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}
func queryAllWebList(queryWebList *[]WebList) {
	rows, err := db.Query("select * from weblist")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		webList := WebList{}
		rows.Scan(&webList.Id, &webList.Name, &webList.WebKey, &webList.Icon)
		*queryWebList = append(*queryWebList, webList)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}
func queryUserData(queryUserData *[]UserData, querySql string, args ...interface{}) {
	rows, err := db.Query(querySql, args...)
	println("查询")
	if err != nil {
		println("查询出错")
		log.Fatal(err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		userData := UserData{}
		rows.Scan(&userData.id, &userData.userId, &userData.webKey, &userData.webData, &userData.timeStamp, &userData.delete)
		*queryUserData = append(*queryUserData, userData)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}

func saveUser(user *User) {
	stmt, err := db.Prepare("insert into user (encryptStr,userPubKey,usermd5) values (?,?,?)")
	if err != nil {
		log.Fatal(err)
	}
	res, err := stmt.Exec(user.encryptStr, user.userPubKey, user.usermd5)
	if err != nil {
		log.Fatal(err)
	}
	lastId, err := res.LastInsertId()
	if err != nil {
		log.Fatal(err)
	}
	user.id = lastId
}
func saveWebList(webList *WebList) {
	stmt, err := db.Prepare("insert into weblist (Name,webkey,Icon) values (?,?,?)")
	if err != nil {
		log.Fatal(err)
	}
	res, err := stmt.Exec(webList.Name, webList.WebKey, webList.Icon)
	if err != nil {
		log.Fatal(err)
	}
	lastId, err := res.LastInsertId()
	if err != nil {
		log.Fatal(err)
	}
	webList.Id = lastId
}
func saveUserData(userData []UserData) {
	// 存放 (?, ?) 的slice
	valueStrings := make([]string, 0, len(userData))
	// 存放values的slice
	valueArgs := make([]interface{}, 0, len(userData)*4)
	// 遍历users准备相关数据
	for _, u := range userData {
		// 此处占位符要与插入值的个数对应
		valueStrings = append(valueStrings, "(?, ?, ?, ?)")
		valueArgs = append(valueArgs, u.userId)
		valueArgs = append(valueArgs, u.webKey)
		valueArgs = append(valueArgs, u.webData)
		valueArgs = append(valueArgs, u.timeStamp)
	}
	insertSql := fmt.Sprintf("INSERT INTO user_data (user_id, web_key,web_data,time_stamp) VALUES %s",
		strings.Join(valueStrings, ","))

	stmt, err := db.Prepare(insertSql)
	if err != nil {
		log.Fatal(err)
	}
	_, err = stmt.Exec(valueArgs...)
	if err != nil {
		log.Fatal(err)
	}

}

func deletedUserData(UserDataList []UserData) (rowCnt int64) {
	// 存放 (?, ?) 的slice
	valueStrings := make([]string, 0, len(UserDataList))

	var userIdList []int64
	for _, value := range UserDataList {
		valueStrings = append(valueStrings, "?")
		userIdList = append(userIdList, value.userId)
	}
	updateSql := fmt.Sprintf("Update User_data set delete=true where Id in (%s)", strings.Join(valueStrings, ","))
	stmt, err := db.Prepare(updateSql)
	if err != nil {
		log.Fatal(err)
	}
	res, err := stmt.Exec(userIdList)
	if err != nil {
		log.Fatal(err)
	}
	rowCnt, err = res.RowsAffected()
	return
}

func getInt(data interface{}) int {
	a, ok := data.(int)
	if !ok {
		panic("类型错误，无法转换成int类型")
	}
	return a
}
func getString(data interface{}) string {
	b, ok := data.([]byte)
	if !ok {
		panic("类型错误，无法转换成string类型")
	}
	return string(b)
}
func getBoll(data interface{}) bool {
	a := getInt(data)
	if a == 0 {
		return false
	}
	return true
}

func loadKey(pubPath string, priPath string) (PubKey *rsa.PublicKey, PriKey *rsa.PrivateKey, err error) {
	//1.获取秘钥（从本地磁盘读取）
	f, err := os.Open(pubPath)
	if err != nil {
		return
	}
	defer f.Close()
	fileInfo, _ := f.Stat()
	b := make([]byte, fileInfo.Size())
	f.Read(b)
	// 2、将得到的字符串解码
	block, _ := pem.Decode(b)
	keyInit, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}
	PubKey = keyInit.(*rsa.PublicKey)

	f, err = os.Open(priPath)
	if err != nil {
		return
	}
	defer f.Close()
	fileInfo, _ = f.Stat()
	b = make([]byte, fileInfo.Size())
	f.Read(b)
	block, _ = pem.Decode(b)                             //解码
	PriKey, err = x509.ParsePKCS1PrivateKey(block.Bytes) //还原数据
	if err != nil {
		return nil, nil, err
	}
	return
}
func RSAGenKey(bits int) error {
	/*
		生成私钥
	*/
	//1、使用RSA中的GenerateKey方法生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	//2、通过X509标准将得到的RAS私钥序列化为：ASN.1 的DER编码字符串
	privateStream := x509.MarshalPKCS1PrivateKey(privateKey)
	//3、将私钥字符串设置到pem格式块中
	block1 := pem.Block{
		Type:  "private key",
		Bytes: privateStream,
	}
	//4、通过pem将设置的数据进行编码，并写入磁盘文件
	fPrivate, err := os.Create("privateKey.pem")
	if err != nil {
		return err
	}
	defer fPrivate.Close()
	err = pem.Encode(fPrivate, &block1)
	if err != nil {
		return err
	}

	/*
		生成公钥
	*/
	publicKey := privateKey.PublicKey
	publicStream, err := x509.MarshalPKIXPublicKey(&publicKey)
	//publicStream:=x509.MarshalPKCS1PublicKey(&publicKey)
	block2 := pem.Block{
		Type:  "public key",
		Bytes: publicStream,
	}
	fPublic, err := os.Create("publicKey.pem")
	if err != nil {
		return err
	}
	defer fPublic.Close()
	pem.Encode(fPublic, &block2)
	return nil
}
func initPub(pubStr string) (PubKey *rsa.PublicKey) {
	block, _ := pem.Decode([]byte(pubStr))
	keyInit, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("Pub密钥错误")
	}
	PubKey = keyInit.(*rsa.PublicKey)
	return
}
func initPri(PriStr string) (PriKey *rsa.PrivateKey) {
	block, _ := pem.Decode([]byte(PriStr)) //解码
	if block == nil {
		panic("")
	} else if block.Type != "PRIVATE KEY" {
		panic("")
	}
	PriKeyInit, err := x509.ParsePKCS8PrivateKey(block.Bytes) //还原数据
	if err != nil {
		panic(err)
	}
	PriKey = PriKeyInit.(*rsa.PrivateKey)
	return
}

//使用公钥加密
func EncyptogRSAPub(src []byte, pubKey *rsa.PublicKey) (res []byte, err error) {
	//4.使用公钥加密数据
	maxLength := pubKey.Size()
	length := 0
	for len(src) > 0 {
		if len(src) > maxLength {
			length = maxLength - 11
		} else {
			length = len(src)
		}
		inputData := src[:length]
		src = src[length:]

		result, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, inputData)
		if err != nil {
			return nil, err
		}
		res = append(res, result...)
	}

	return
}

//使用公钥解密
//func DecrptogRSAPub(src []byte, pubKey *rsa.PublicKey) (res []byte, err error) {
//	grsa := gorsa.RSASecurity{}
//	grsa.SetPublicKeyPoint(pubKey)
//	res, err = grsa.PubKeyDECRYPT(src)
//	if err != nil {
//		return nil, err
//	}
//
//	//maxLength := pubKey.Size()
//	//length := 0
//	//for len(src) > 0 {
//	//	if len(src) > maxLength {
//	//		length = maxLength - 11
//	//	} else {
//	//		length = len(src)
//	//	}
//	//	inputData := src[:length]
//	//	src = src[length:]
//	//
//	//	result, err := grsa.PubKeyDECRYPT(inputData)
//	//	if err != nil {
//	//		return nil, err
//	//	}
//	//	res = append(res, result...)
//	//}
//	return
//}

//使用私钥解密
func DecrptogRSA(src []byte, privateKey *rsa.PrivateKey) (res []byte, err error) {
	maxLength := privateKey.Size()
	length := 0
	for len(src) > 0 {
		if len(src) > maxLength {
			length = maxLength
		} else {
			length = len(src)
		}
		inputData := src[:length]
		src = src[length:]

		result, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, inputData)
		if err != nil {
			return nil, err
		}
		res = append(res, result...)
	}

	return
}

//使用私钥加密
//func EncyptogRSAPri(src []byte, privateKey *rsa.PrivateKey) (res []byte, err error) {
//	grsa := gorsa.RSASecurity{}
//	grsa.SetPrivateKeyPoint(privateKey)
//	res, err = grsa.PriKeyENCTYPT(src)
//	if err != nil {
//		return nil, err
//	}
//
//	return
//}
