package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	limits "github.com/gin-contrib/size"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nufangqiangwei/timewheel"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	db    *gorm.DB
	Timer *timeWheel.TimeWheel
	Log   *log.Logger
	err   error
)

const maxFileData = 10 << 20
const staticFilePath = ""

func checkUserFunc(ctx *gin.Context) {
	jsonParams := make(map[string]interface{})

	err := ctx.BindJSON(&jsonParams)
	if err != nil {
		fmt.Printf("%+v", err)
		ctx.JSON(http.StatusBadRequest, ErrResponse{Code: 404, Message: "参数错误"})
		return
	}
	EncryptStr, _ := jsonParams["EncryptStr"].(string)
	if EncryptStr == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 400, Message: "缺少参数"})
		ctx.Abort()
		return
	}

	sysConfig := &SysConfig{}
	db.First(sysConfig, "config_key=?", "webPriKey")
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
	data := EncryptData{}
	err = json.Unmarshal(encryptStr, &data)
	if err != nil {
		println(err.Error())
		ctx.JSON(http.StatusOK, ErrResponse{Code: 413, Message: "密钥错误"})
		ctx.Abort()
		return
	}
	user := &User{}
	db.First(user, "id=?", data.UserId)
	if user.UserMd5 == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "用户错误"})
		ctx.Abort()
		return
	}
	if data.EncryptStr != user.EncryptStr || time.Now().Unix()-data.Timestamp > 60 {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 400, Message: "密钥错误"})
		ctx.Abort()
		return
	}

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
	UserData   []UserDataForm `json:"UserData"`
}
type WebListForm struct {
	Name   string `from:"Name" binding:"required"`
	WebKey string `from:"WebKey" binding:"required"`
	Icon   string `from:"Icon"`
}
type CopyMessageForm struct {
	Message string `from:"message"`
	File    bool   `from:"haveFile"`
	OutTime int    `from:"outTime"`
	Public  bool   `from:"public"` //是否公开，不公开需要登录账号
}
type EncryptData struct {
	UserId     int64
	EncryptStr string
	Timestamp  int64
}

// model
type User struct {
	Id         int64 `gorm:"primaryKey"`
	EncryptStr string
	UserPubKey string
	UserMd5    string
}
type SysConfig struct {
	ConfigKey   string `gorm:"primaryKey"`
	ConfigValue string
}
type WebList struct {
	Id     int64 `gorm:"primaryKey"`
	Name   string
	WebKey string
	Icon   string
}
type UserData struct {
	Id        int64 `gorm:"primaryKey"`
	UserId    int64
	WebKey    string
	WebData   string
	TimeStamp int64
	Deleted   bool
}
type SynchronousMessage struct {
	Id         int64 `gorm:"primaryKey"`
	UserId     int64
	Message    string // 提交的文本内容
	HaveFile   bool   // 是否提交文件
	AddTime    int64  // 添加时间
	ExpireTime int    // 过期时间
}
type UserFile struct {
	Id            int64 `gorm:"primaryKey"`
	UserId        int64
	SynchronousId int64  // 同步信息的id
	FileName      string // 文件原始名
	FileAgainName string // 文件保存名
	FilePath      string // 文件地址
	AddTime       int64  // 添加时间
	ExpireTime    int    // 过期时间
}

func init() {
	//"passwordTest"
	//"mypassword"
	dsn := "qiangwei:Qiangwei@tcp(101.32.15.231:6603)/passwordTest?charset=utf8mb4&parseTime=True&loc=Local"
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "",
			SingularTable: true,
		},
		Logger: logger.Default.LogMode(logger.Info),
	})
	//db, _ = sql.Open("mysql", "qiangwei:Qiangwei@tcp(101.32.15.231:6603)/mypassword")
	logFile, err := os.OpenFile("timeWheelRun.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("open file error !")
	}
	Log = log.New(logFile, "[dev]", log.LstdFlags)
	Log.SetOutput(logFile)

	Timer = timeWheel.NewTimeWheel(&timeWheel.WheelConfig{IsRun: true, Log: Log})

}
func main() {
	defaultApp := gin.Default()
	app := defaultApp.Group("/password/api")
	app.POST("/register", registerView)
	app.GET("/webList", getWebListView)
	app.POST("/SaveText", uploadMessageOrFile)

	checkUser := app.Use(checkUserFunc)
	{
		checkUser.POST("/SaveUserData", saveUserDataView)
		checkUser.POST("/GetUserData", getUserDataView)
		checkUser.POST("/AppendWebAddress", AppendWebListView)
	}
	app.Use(limits.RequestSizeLimiter(maxFileData))
	//app.Run(":8080")
	defaultApp.Run(":5000")

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
	db.First(&user, "user_mad5=?", userMd5)
	sysConfig := &SysConfig{}
	db.First(sysConfig, "config_key=?", "webPriKey")
	if sysConfig.ConfigValue == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "系统没有添加私钥"})
		return
	}
	if user.UserMd5 != "" {
		ctx.JSON(http.StatusOK, registerResponse{Code: 200, UserId: user.Id, WebPubKey: sysConfig.ConfigValue, EncryptStr: user.EncryptStr})
		return
	}
	user.UserMd5 = userMd5
	user.EncryptStr = form.EncryptStr
	user.UserPubKey = form.UserPubKey
	db.Create(&user)
	ctx.JSON(http.StatusOK, registerResponse{Code: 200, UserId: user.Id, WebPubKey: sysConfig.ConfigValue, EncryptStr: user.EncryptStr})

}
func getWebListView(ctx *gin.Context) {
	var queryWebList []WebList
	db.Find(queryWebList)
	ctx.JSON(http.StatusOK, map[string]interface{}{"code": 200, "message": "ok", "data": queryWebList})
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
	//db.Find(&queryUserDataList, "user_id=?", user.Id).Where("web_key IN ?", webKeyList).Where("deleted", false)
	db.Where("user_id=?", user.Id).Where("web_key IN ?", webKeyList).Where("deleted", false).Find(&queryUserDataList)

	if len(queryUserDataList) > 0 {
		var deleteId []int64
		for _, aa := range queryUserDataList {
			deleteId = append(deleteId, aa.Id)
		}
		db.Model(UserData{}).Where("id in ?", deleteId).Update("deleted", true)
	}

	timeStamp = time.Now().Unix()
	for _, value := range form.UserData {
		saveUserDtaList = append(saveUserDtaList, UserData{
			UserId:    user.Id,
			WebKey:    value.WebKey,
			WebData:   value.WebData,
			TimeStamp: timeStamp,
		})
	}
	db.Create(&saveUserDtaList)
	ctx.JSON(http.StatusOK, Response{Code: 200, Message: "ok", Data: []interface{}{}})
}
func getUserDataView(ctx *gin.Context) {
	var queryUserDataList []UserData
	lastPushTime := ctx.Request.PostFormValue("lastPushTime")
	user := getRequestUser(ctx)

	if lastPushTime == "" {
		db.Find(&queryUserDataList, "user_id=?", user.Id)
	} else {
		db.Find(&queryUserDataList, "user_id=?", user.Id, "time_stamp=?", lastPushTime)
	}

	result := make(map[string]interface{}, 0)
	for _, value := range queryUserDataList {
		result[value.WebKey] = value.WebData
	}
	ctx.JSON(http.StatusOK, map[string]interface{}{"code": 200, "message": "ok", "data": result})
}
func AppendWebListView(ctx *gin.Context) {
	var form WebListForm

	if ctx.ShouldBind(&form) != nil {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "参数错误"})
		return
	}
	var Web WebList
	db.First(&Web, "WebKey=?", form.WebKey)
	if Web.Id != 0 {
		ctx.JSON(http.StatusOK, map[string]interface{}{"Code": 400, "Message": "该网站已添加"})
	}
	Web.Name = form.Name
	Web.WebKey = form.WebKey
	Web.Icon = form.Icon
	db.Create(&Web)
	ctx.JSON(http.StatusOK, map[string]interface{}{"Code": 200, "Message": "ok"})
}
func uploadMessageOrFile(ctx *gin.Context) {
	var (
		form      CopyMessageForm
		message   SynchronousMessage
		fileModel []UserFile
		err       error
	)
	if ctx.ShouldBind(&form) != nil {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "参数错误"})
		return
	}
	message.Message = ctx.PostForm("message")
	ctx.DefaultPostForm("outTime", "7200")
	if form.OutTime == 0 {
		message.ExpireTime = 3600 * 2
	}
	if form.Public {
		checkUserFunc(ctx)
		user := getRequestUser(ctx)
		message.UserId = user.Id
	}
	if form.File {
		// 储存文件
		//ctx.FormFile("file") // *multipart.FileHeader
		// 限制上传文件大小
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxFileData)
		// 限制放入内存的文件大小
		if ctx.Request.ParseMultipartForm(maxFileData) != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"msg": "文件读取失败"})
			return
		}
		fileForm, _ := ctx.MultipartForm() // *multipart.Form
		fileModel, err = savePostUserFiles(fileForm.File["upload[]"], message.UserId, message.ExpireTime)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"msg": "文件保存异常" + err.Error()})
			return
		}
		message.HaveFile = true
	}
	message.AddTime = time.Now().Unix()
	db.Create(&message)
	for _, userFileModel := range fileModel {
		userFileModel.SynchronousId = message.Id
		db.Create(&userFileModel)
	}
	// 设置删除文件
	Timer.AppendOnceFunc(removeCopyMessage, "", "", timeWheel.Crontab{
		ExpiredTime: int64(form.OutTime),
	})
}

// 储存用户上传的文件
// 保存文件，修改文件名，原始文件名保存到数据库中
func savePostUserFiles(files []*multipart.FileHeader, userid int64, expireTime int) (result []UserFile, err error) {
	ti := time.Now()
	folderPath := fmt.Sprintf("%s\\%d\\%d\\%d", staticFilePath, ti.Year(), ti.Month(), ti.Day())
	if !filePathExists(folderPath) {
		_ = os.MkdirAll(folderPath, os.ModePerm)
	}
	var saveFile []string
	removeFile := func() {
		for _, filePath := range saveFile {
			_ = os.Remove(filePath)
		}
	}
	for _, file := range files {
		fileUuid := uuid.New()
		requestFile, err := file.Open()
		if err != nil {
			removeFile()
			return nil, err
		}
		filePath := folderPath + "\\" + fileUuid.String()
		fi, err := os.Create(filePath)
		if err != nil {
			removeFile()
			return nil, err
		}
		_, err = io.Copy(fi, requestFile)
		if err != nil {
			removeFile()
			return nil, err
		}
		result = append(result, UserFile{
			UserId:        userid,
			FileName:      file.Filename,
			FileAgainName: fileUuid.String(),
			FilePath:      filePath,
			AddTime:       ti.Unix(),
			ExpireTime:    expireTime,
		})
		saveFile = append(saveFile, filePath)
	}
	return result, nil
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

// FirstLower 字符串首字母小写
func FirstLower(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToLower(s[:1]) + s[1:]
}
func getRequestUser(ctx *gin.Context) (user *User) {
	user, ok := ctx.Keys["user"].(*User)
	if !ok {
		log.Printf("获取用户失败")
		panic("获取用户失败")
	}
	return
}
func filePathExists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}
func fileExist(path string) bool {
	//err := syscall.Access(path, syscall.F_OK)
	//return !os.IsNotExist(err)
	return false
}

// 定时删除用户同步的数据
func removeCopyMessage(data interface{}) {

}
