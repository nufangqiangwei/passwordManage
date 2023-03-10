package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	limits "github.com/gin-contrib/size"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
	"github.com/nufangqiangwei/timewheel"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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
)

const (
	maxFileData      = 10 << 20
	staticFilePath   = ""
	flagUserName     = "root"
	flagPassword     = "]=[-p0o9"
	flagReadonly     = false
	flagRootDir      = "/home/ubuntu/webDAV"
	databasePassword = "]=[-p0o9"
)

func checkUser(ctx *gin.Context, EncryptStr string, signed string) (result bool) {
	sysConfig := &SysConfig{}
	db.First(sysConfig, "config_key=?", "privateKeyStr")
	if sysConfig.ConfigValue == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "系统没有添加私钥"})
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
		return
	}
	data := EncryptData{}
	err = json.Unmarshal(encryptStr, &data)
	if err != nil {
		println(err.Error())
		ctx.JSON(http.StatusOK, ErrResponse{Code: 413, Message: "token错误"})
		return
	}
	user := &User{}
	db.First(user, "id=?", data.UserId)
	if user.UserMd5 == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "用户错误"})
		return
	}
	println(user.UserPubKey)
	if RSAVerifySign(initPub(user.UserPubKey), signed, user.EncryptStr) != nil || time.Now().UnixMilli()-data.Timestamp > 60000 {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 400, Message: "密钥错误"})
		return
	}
	ctx.Set("user", user)
	result = true
	return
}
func checkUserFunc(ctx *gin.Context) {
	jsonParams := make(map[string]interface{})

	err := ctx.BindJSON(&jsonParams)
	if err != nil {
		fmt.Printf("%+v", err)
		ctx.JSON(http.StatusBadRequest, ErrResponse{Code: 404, Message: "参数错误"})
		ctx.Abort()
		return
	}
	EncryptStr, _ := jsonParams["EncryptStr"].(string)
	if EncryptStr == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 400, Message: "缺少参数"})
		ctx.Abort()
		return
	}
	signed, _ := jsonParams["Signed"].(string)
	if signed == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 400, Message: "缺少参数"})
		ctx.Abort()
		return
	}
	if !checkUser(ctx, EncryptStr, signed) {
		ctx.Abort()
		return
	}
	bodyParams, err := json.Marshal(jsonParams)
	if err != nil {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 500, Message: "写入错误"})
		ctx.Abort()
		return
	}
	ctx.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyParams))
}
func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method               //请求方法
		origin := c.Request.Header.Get("Origin") //请求头部
		var headerKeys []string                  // 声明请求头keys
		for k := range c.Request.Header {
			headerKeys = append(headerKeys, k)
		}
		headerStr := strings.Join(headerKeys, ", ")
		if headerStr != "" {
			headerStr = fmt.Sprintf("access-control-allow-origin, access-control-allow-headers, %s", headerStr)
		} else {
			headerStr = "access-control-allow-origin, access-control-allow-headers"
		}
		originDomains := []string{"http://test.j.cn"}
		inArraysFlag := false
		for _, value := range originDomains {
			if origin == value {
				inArraysFlag = true
				break
			}
		}

		if origin != "" && inArraysFlag {
			// 这是允许访问所有域
			c.Header("Access-Control-Allow-Origin", origin)
			//服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE")
			//  header的类型
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session,X_Requested_With,Accept, Origin, Host, Connection, Accept-Encoding, Accept-Language,DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Pragma")
			// 允许跨域设置 可以返回其他子段
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers,Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma,FooBar") // 跨域关键设置 让浏览器可以解析
			c.Header("Access-Control-Max-Age", "172800")                                                                                                                                                           // 缓存请求信息 单位为秒
			c.Header("Access-Control-Allow-Credentials", "false")                                                                                                                                                  //  跨域请求是否需要带cookie信息 默认设置为true
			c.Set("content-type", "application/json")                                                                                                                                                              // 设置返回格式是json
		}

		//放行所有OPTIONS方法
		if method == "OPTIONS" {
			c.JSON(http.StatusOK, "Options Request!")
		}
		// 处理请求
		c.Next() //  处理请求
	}
}

type ErrResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type registerResponse struct {
	Code       int    `json:"code"`
	UserId     int64  `json:"userId"`
	WebPubKey  string `json:"webPubKey"`
	EncryptStr string `json:"encryptStr"`
}
type Response struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Data    []interface{} `json:"data"`
}

// request Model
type registerForm struct {
	UserPubKey string `from:"UserPubKey" binding:"required"`
	EncryptStr string `from:"EncryptStr" binding:"required"`
}
type UserDataForm struct {
	DataKey string `json:"DataKey"`
	Value   string `json:"Value"`
}
type saveUserDataForm struct {
	EncryptStr string         `json:"EncryptStr"`
	DataType   string         `json:"DataType"`
	UserData   []UserDataForm `json:"UserData"`
}
type WebListForm struct {
	Name   string `from:"Name" binding:"required"`
	WebKey string `from:"DataKey" binding:"required"`
	Icon   string `from:"Icon"`
}
type CopyMessageForm struct {
	Message string `json:"message"`
	File    bool   `json:"haveFile"`
	OutTime int64  `json:"outTime"`
	Public  bool   `json:"public"` //是否公开，不公开需要登录账号
}
type EncryptData struct {
	UserId    int64
	Timestamp int64
}
type GetUserData struct {
	EncryptStr string
	DataType   string
	Version    int64
}

// database Model
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
	Id     int64  `gorm:"primaryKey" json:"id"`
	Name   string `json:"name"`
	WebKey string `json:"webKey"`
	Icon   string `json:"icon"`
}
type UserData struct {
	Id        int64 `gorm:"primaryKey"`
	UserId    int64
	DataType  string // 数据类型
	DataKey   string
	Value     string
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
	var err error
	//dsn := "qiangwei:Qiangwei@tcp(101.32.15.231:6603)/mypassword?charset=utf8mb4&parseTime=True&loc=Local&readTimeout=300s"
	db, err = gorm.Open(sqlite.Open("passwordData.db"), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "",
			SingularTable: true,
		},
		//Logger: logger.Default.LogMode(logger.Info),
	})
	logFile, err := os.OpenFile("webRun.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("open file error !")
	}
	//gin.DefaultWriter = logFile
	//gin.DefaultErrorWriter = logFile
	Log = log.New(logFile, "[dev]", log.LstdFlags)
	Log.SetOutput(logFile)
	err = db.AutoMigrate(&User{}, &SysConfig{}, &WebList{}, &UserData{}, SynchronousMessage{}, &UserFile{})
	if err != nil {
		Log.Println("创建表错误")
		return
	}
	Timer = timeWheel.NewTimeWheel(&timeWheel.WheelConfig{IsRun: true, Log: Log, BeatSchedule: []timeWheel.Task{
		{Job: func(i interface{}) {
			s, err := backupSqlite()
			if err != nil {
				return
			}
			Log.Println("备份完成", s)
		},
			JobData: "",
			Repeat:  true,
			Crontab: timeWheel.Crontab{Hour: "2", Minute: "30"},
			JobName: "备份",
		},
	},
	})
}
func main() {
	//gin.SetMode(gin.ReleaseMode)
	defaultApp := gin.Default()
	defaultApp.Use(func(context *gin.Context) {
		Log.Println("++++++++++++++++++++++++++++++新请求++++++++++++++++++++++++++++++")
	})
	defaultApp.Use(Cors())
	defaultApp.POST("/register", registerView)
	defaultApp.GET("/webList", getWebListView)
	defaultApp.POST("/SaveText", uploadMessageOrFile)
	defaultApp.GET("/error", getError)
	defaultApp.POST("/error", postError)
	defaultApp.GET("/getRandomImageList", getRandomImageList)
	checkUser := defaultApp.Use(checkUserFunc)
	{
		checkUser.POST("/SaveUserData", saveUserDataView)
		checkUser.POST("/GetUserData", getUserDataView)
		checkUser.POST("/AppendWebAddress", AppendWebListView)
	}
	defaultApp.Use(limits.RequestSizeLimiter(maxFileData))
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
	db.First(&user, "user_md5=?", userMd5)
	sysConfig := &SysConfig{}
	db.First(sysConfig, "config_key=?", "publicKeyStr")
	if sysConfig.ConfigValue == "" {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "系统没有添加密钥"})
		return
	}
	if user.Id != 0 {
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
	db.Find(&queryWebList)
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
	err := ctx.BindJSON(&form)
	if err != nil {
		println(err.Error())
		ctx.JSON(http.StatusOK, ErrResponse{Code: 403, Message: "参数错误"})
		return
	}

	for _, value := range form.UserData {
		webKeyList = append(webKeyList, value.DataKey)
	}
	user = getRequestUser(ctx)

	db.Where("user_id=?", user.Id).Where("web_key IN ?", webKeyList).Find(&queryUserDataList)
	timeStamp = time.Now().Unix()
	for _, value := range form.UserData {
		saveUserDtaList = append(saveUserDtaList, UserData{
			UserId:    user.Id,
			DataKey:   value.DataKey,
			Value:     value.Value,
			TimeStamp: timeStamp,
		})
	}
	if len(saveUserDtaList) > 0 {
		db.Create(&saveUserDtaList)
	}

	ctx.JSON(http.StatusOK, Response{Code: 200, Message: "ok", Data: []interface{}{}})
}
func getUserDataView(ctx *gin.Context) {
	var (
		queryUserDataList []UserData
		jsonData          GetUserData
	)

	err := ctx.BindJSON(&jsonData)
	if err != nil {
		fmt.Printf("%+v", err)
		ctx.JSON(http.StatusBadRequest, ErrResponse{Code: 404, Message: "参数错误"})
		return
	}
	user := getRequestUser(ctx)

	db.Where("id IN (?)",
		db.Select("max(id)").Where("user_id=? and data_type=?", user.Id, jsonData.DataType).Group("data_key").Table("user_data"),
	).Table("user_data").Find(&queryUserDataList)
	result := make([]map[string]string, 0)
	for _, value := range queryUserDataList {
		result = append(result, map[string]string{"webKey": value.DataKey, "webData": value.Value})
	}
	ctx.JSON(http.StatusOK, map[string]interface{}{"code": 200, "message": "ok", "data": result, "version": jsonData.Version})
}
func AppendWebListView(ctx *gin.Context) {
	var form WebListForm

	if ctx.ShouldBind(&form) != nil {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 404, Message: "参数错误"})
		return
	}
	var Web WebList
	db.First(&Web, "DataKey=?", form.WebKey)
	if Web.Id != 0 {
		ctx.JSON(http.StatusOK, map[string]interface{}{"Code": 400, "Message": "该网站已添加"})
	}
	Web.Name = form.Name
	Web.WebKey = form.WebKey
	Web.Icon = form.Icon
	db.Create(&Web)
	ctx.JSON(http.StatusOK, map[string]interface{}{"code": 200, "message": "ok"})
}
func uploadMessageOrFile(ctx *gin.Context) {
	var (
		form      CopyMessageForm
		message   SynchronousMessage
		fileModel []UserFile
		err       error
	)

	formMessage := ctx.DefaultPostForm("message", "")
	requestBody := fmt.Sprintf(`{"message":"","haveFile":%s,"outTime":%s,"public":%s}`,
		ctx.DefaultPostForm("haveFile", "false"),
		ctx.DefaultPostForm("outTime", "7200"),
		ctx.DefaultPostForm("public", "false"),
	)
	err = json.Unmarshal([]byte(requestBody), &form)
	if err != nil {
		println(err.Error())
		println(requestBody)
		return
	}
	form.Message = formMessage

	message.Message = form.Message
	if form.OutTime == 0 {
		message.ExpireTime = 3600 * 2
		form.OutTime = 3600 * 2
	}
	if form.Public {
		if !checkUser(ctx, ctx.DefaultPostForm("EncryptStr", ""), ctx.DefaultPostForm("Signed", "")) {
			ctx.Abort()
			return
		}
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
		fmt.Printf("上传文件详情 %+v\n\n", fileForm.File)
		fileModel, err = savePostUserFiles(fileForm.File["files"], message.UserId, message.ExpireTime)
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
		ExpiredTime: form.OutTime,
	})
	ctx.JSON(http.StatusOK, Response{})
	ctx.JSON(http.StatusOK, Response{})
}
func getRandomImageList(ctx *gin.Context) {
	// 来源网站：煎蛋，instagram, twitter
	ctx.JSON(200, map[string][]string{
		"msg": {
			"http://192.168.111.45/0081ffzKly8h9eorghkayj32c03407wh.jpg",
			"http://192.168.111.45/0081ffzKly8h9eotamm3jj31jk2bcdlv.jpg",
			"http://192.168.111.45/699a48a7ly1h0qsgdv68ej221s33zhdv.jpg",
			"http://192.168.111.45/69618f6fly1h6lkc0f9bcj20r01ewjsh.jpg",
			"http://192.168.111.45/4886703f9a211808c140d32529149394.jpg",
			"http://192.168.111.45/008vVelsly1ha6tt89lhnj30cf0jgn0g.jpg",
			"http://192.168.111.45/008vVelsly1ha6q1g1dxyj30rs2yztud.jpg",
			"http://192.168.111.45/008vVelsly1ha6prq6bwsj311y1kw1i1.jpg",
			"http://192.168.111.45/008vVelsly1ha6prk8y1xj316o1kw4mo.jpg",
			"http://192.168.111.45/008vVelsly1ha6kbkuq5cj30lb0lc418.jpg",
		},
	})
}

// 储存用户上传的文件
// 保存文件，修改文件名，原始文件名保存到数据库中
func savePostUserFiles(files []*multipart.FileHeader, userid int64, expireTime int) (result []UserFile, err error) {
	ti := time.Now()
	folderPath := fmt.Sprintf("%s\\%d\\%d\\%d", staticFilePath, ti.Year(), ti.Month(), ti.Day())
	if !filePathExists(folderPath) {
		err := os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			print("创建文件夹出错")
			println(err.Error())
		}
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

// EncyptogRSAPub 使用公钥加密
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

// DecrptogRSA 使用私钥解密
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

func RSASign(privateKey *rsa.PrivateKey, signStr string) (string, error) {
	hashMD5 := md5.New()
	hashMD5.Write([]byte(signStr))
	Digest := hashMD5.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.Hash(0), Digest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

// RSAVerifySign signData 密文，signStr 明文
func RSAVerifySign(pubKey *rsa.PublicKey, signData string, signStr string) error {
	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	hash := sha1.New()
	hash.Write([]byte(signStr))
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hash.Sum(nil), sign)
}

// FirstLower 字符串首字母小写
func FirstLower(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToLower(s[:1]) + s[1:]
}
func getRequestUser(ctx *gin.Context) (user *User) {
	data, ok := ctx.Get("user")
	if !ok {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 500, Message: "写入错误"})
		ctx.Abort()
	}

	user, ok = data.(*User)
	if !ok {
		ctx.JSON(http.StatusOK, ErrResponse{Code: 500, Message: "内部错误"})
		ctx.Abort()
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

func getError(ctx *gin.Context) {
	println(ctx.Query("msg"))
}
func postError(ctx *gin.Context) {
	a := map[string]string{}
	ctx.BindJSON(&a)
	fmt.Printf("%v\n", a)
}

// 备份
func backupSqlite() (string, error) {
	ctx := context.Background()
	// 备份到临时文件

	tmpFile, err := ioutil.TempFile(``, fmt.Sprintf(`serverSqliteDb-*-%s.db`, time.Now().Format("2006-01-02")))
	if err != nil {
		return ``, err
	}
	tmpFile.Close()

	// 目的数据库
	dstDB, err := sql.Open(`sqlite3`, tmpFile.Name())
	if err != nil {
		return ``, err
	}
	defer dstDB.Close()

	dstConn, err := dstDB.Conn(ctx)
	if err != nil {
		return ``, err
	}
	defer dstConn.Close()

	if err := dstConn.Raw(func(dstDC interface{}) error {
		rawDstConn := dstDC.(*sqlite3.SQLiteConn)

		s := db.ConnPool.(*sql.DB)
		srcConn, err := s.Conn(ctx)
		// 源数据库
		//srcConn, err := s.db.Conn(ctx)
		if err != nil {
			return err
		}
		defer srcConn.Close()

		if err := srcConn.Raw(func(srcDC interface{}) error {
			rawSrcConn := srcDC.(*sqlite3.SQLiteConn)

			// 备份函数调用
			backup, err := rawDstConn.Backup(`main`, rawSrcConn, `main`)
			if err != nil {
				return err
			}

			// errors can be safely ignored.
			_, _ = backup.Step(-1)

			if err := backup.Close(); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return ``, err
	}

	return tmpFile.Name(), nil
}
