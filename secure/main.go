package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

const SIZE int64 = 1024 << 20


func randomFilename(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63() % int64(len(letterBytes))]
	}
	return string(b)
}


func ping(c *gin.Context){
	c.JSON(http.StatusOK, gin.H{"message": "pong"})
}

func register(c *gin.Context){

	type creds struct {
		Username string `form:"username" validate:"required,min=6,max=20"`
		Password string `form:"password" validate:"required,min=8,max=20"`
		Confirm_pass string `form:"confirm-password" validate:"required,eqfield=Password"`
	}

	var uploadData creds

	if err := c.Bind(&uploadData); err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"message": "Bad request"})
		return
	}
	val := validator.New()
	err := val.Struct(uploadData)
	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"message": "Username and password required"})
		return
	}

	userExist, res := usernameExists(uploadData.Username)
	if res != "" {
		fmt.Println("Error in register", res)
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"message": res})
		return
	}
	if userExist {
		c.HTML(http.StatusConflict, "register.html", gin.H{"message": "User already exists"})
		return
	}

	id := getUUID()
	hashedPassword := hashPass(uploadData.Password)
	dir_name := filepath.Join("/storage/" + id)
	err = os.Mkdir(dir_name, 0666)

	if err != nil{
		fmt.Println(err.Error())
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"message": "Server Error"})
		return
	}

	status := registerUser(id, uploadData.Username, hashedPassword)
	if status != ""{
		os.Remove(dir_name)
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"message": status})
		return
	}

	c.HTML(http.StatusOK, "register.html", gin.H{"message": "User registered successfully"})
}


func login(c *gin.Context) {

	type creds struct {
		Username string `form:"username" validate:"required,min=5,max=20"`
		Password string `form:"password" validate:"required,min=6,max=20"`
	}

	var uploadData creds

	if err := c.Bind(&uploadData); err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{"message": "Bad request"})
		return
	}
	val := validator.New()
	err := val.Struct(uploadData)
	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"message": "Invalid Credentials"})
		return
	}
	password := hashPass(uploadData.Password)
	userExists, id := validateUser(uploadData.Username, password)
	if !userExists {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"message": id})
		return
	}
	token, status := generateToken(id)
	if status != "" {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{"message": status})
		return
	}
	c.SetCookie("token", token, 60 * 30, "/", "", false, true)
	c.Redirect(http.StatusFound, "/")
}

func upload(c *gin.Context){

	token, err := c.Cookie("token")
	if err != nil {
		fmt.Println(err.Error())
		c.SetCookie("token", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
		return
	}
	isOK, id := verifyToken(token)
	if !isOK {
		c.SetCookie("token", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
		return
	}

	file, err := c.FormFile("file")
	if file == nil {
		c.HTML(http.StatusBadRequest, "upload.html", gin.H{"message": "Invalid request - file not provided"})
		return
	}
	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"message": "error in file upload"})
		return
	}

	if file.Size > SIZE {
		c.HTML(http.StatusExpectationFailed, "upload.html", gin.H{"message": "file size exceeded (" + fmt.Sprintf("%d", SIZE / (1 << 20)) + "MB)"})
		return
	}

	password := c.PostForm("password")
	if password == "" {
		c.HTML(http.StatusBadRequest, "upload.html", gin.H{"message": "Invalid request - password not provided"})
		return
	}

	password = SHA256Hash(password)

	mod_pass, err := hex.DecodeString(password)
	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"message": "ServerError"})
		return
	}

	tmp := filepath.Join("/tmp/", randomFilename(10))

	err = c.SaveUploadedFile(file, tmp)
	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"message": "ServerError"})
		return
	}

	file_new, err := file.Open()
	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"message": "ServerError"})
		return
	}
	defer file_new.Close()

	hash, err := hashMD5(file_new)
	if err != nil{
		c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"message": "ServerError"})
		return
	}

	fileExists, status, _ := checkFile(hash, id)
	if fileExists {
		c.HTML(http.StatusBadRequest, "upload.html", gin.H{"message": status})
		os.Remove(tmp)
		return
	}

	status, err = encryptAES(tmp, mod_pass, id, hash)
	if status != "" {
		if err == os.ErrExist{
			c.HTML(http.StatusBadRequest, "upload.html", gin.H{"message": "file already exists"})
			os.Remove(tmp)
			return
		}
		if err == os.ErrNotExist{
			c.HTML(http.StatusBadRequest, "upload.html", gin.H{"message": "error in ID"})
			fmt.Println("Token malfunction")
			c.SetCookie("token", "", -1, "/", "", false, true)
			c.Redirect(http.StatusFound, "/")
			generateKey()
			os.Remove(tmp)
			return
		}
		fmt.Println(err.Error())
		c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"message": "ServerError"})
		os.Remove(tmp)
		return
	}

	os.Remove(tmp)
	status = updateTable(id, hash, file.Filename, "insert")
	if status != "" {
		os.Remove(filepath.Join("/storage/", id, hash))
		c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"message": "Error in uploading file"})
		return
	}

	c.HTML(http.StatusOK, "upload.html", gin.H{"message": "file uploaded successfully"})
}


func download(c *gin.Context){
	token, err := c.Cookie("token")
	var filelist []fileData

	if err != nil {
		fmt.Println(err.Error())
		c.SetCookie("token", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
		return
	}
	isOK, id := verifyToken(token)
	if !isOK {
		c.SetCookie("token", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
		return
	}

	isOK, filelist = listFiles(id)
	length := len(filelist)
	if !isOK{
		c.HTML(http.StatusInternalServerError, "home.html", gin.H{"message": "ServerError", "files": filelist, "length": length})
		return
	}

	filehash := c.PostForm("filehash")
	if filehash == ""{
		c.HTML(http.StatusBadRequest, "home.html", gin.H{"message": "Invalid request - filehash", "files": filelist, "length": length})
		return
	}

	password := c.PostForm("password")
	if password == "" {
		c.HTML(http.StatusBadRequest, "home.html", gin.H{"message": "Invalid request - password", "files": filelist, "length": length})
		return
	}
	password = SHA256Hash(password)
	mod_pass, err := hex.DecodeString(password)
	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusInternalServerError, "home.html", gin.H{"message": "ServerError", "files": filelist, "length": length})
		return
	}

	fileExists, status, filename := checkFile(filehash, id)
	if !fileExists {
		c.HTML(http.StatusBadRequest, "home.html", gin.H{"message": status, "files": filelist, "length": length})
		return
	}

	readfile := filepath.Join("/storage/", id, filehash)
	status, err = decryptAES(readfile, filename, mod_pass)

	if status != "" {
		fmt.Println(err.Error())
		c.HTML(http.StatusUnauthorized, "home.html", gin.H{"message": "Incorrect password", "files": filelist, "length": length})
		return
	}

	saved_path := filepath.Join("/tmp", filename)
	c.Header("Content-Description", "File Transfer")
	c.FileAttachment(saved_path, filename)
	c.Done()
	os.Remove(saved_path)
}


func delete(c *gin.Context){
	token, err := c.Cookie("token")
	var filelist []fileData

	if err != nil {
		fmt.Println(err.Error())
		c.SetCookie("token", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
		return 
	}
	isOK, id := verifyToken(token)
	if !isOK{
		c.SetCookie("token", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
		return
	}
	isOK, filelist = listFiles(id)
	length := len(filelist)
	if !isOK{
		c.HTML(http.StatusInternalServerError, "home.html", gin.H{"message": "ServerError", "files": filelist, "length": length})
		return
	}

	filehash := c.PostForm("filehash")
	if filehash == ""{
		c.HTML(http.StatusBadRequest, "home.html", gin.H{"message": "Invalid request - filehash", "files": filelist, "length": length})
		return
	}

	password := c.PostForm("password")
	if password == "" {
		c.HTML(http.StatusBadRequest, "home.html", gin.H{"message": "Invalid request - password", "files": filelist, "length": length})
		return
	}
	password = SHA256Hash(password)
	mod_pass, err := hex.DecodeString(password)
	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusInternalServerError, "home.html", gin.H{"message": "ServerError", "files": filelist, "length": length})
		return
	}
	
	fileExists, status, filename := checkFile(filehash, id)
	if !fileExists {
		c.HTML(http.StatusBadRequest, "home.html", gin.H{"message": status, "files": filelist, "length": length})
		return
	}

	readfile := filepath.Join("/storage/", id, filehash)
	status, err = decryptAES(readfile, filename, mod_pass)

	if status != "" {
		fmt.Println(err.Error())
		c.HTML(http.StatusUnauthorized, "home.html", gin.H{"message": "Incorrect password", "files": filelist, "length": length})
		return
	}

	status = updateTable(id, filehash, filename, "delete")
	if status != "" {
		c.HTML(http.StatusOK, "home.html", gin.H{"message": "Error in deleting file", "files": filelist, "length": length})
		return
	}
	_, filelist = listFiles(id)
	length = len(filelist)

	os.Remove(readfile)
	os.Remove(filepath.Join("/tmp/", filename))
	c.HTML(http.StatusOK, "home.html", gin.H{"message": "File removed successfully", "files": filelist, "length": length})
}


func home(c *gin.Context){
	token, err := c.Cookie("token")
	var filelist []fileData

	if err != nil {
		fmt.Println(err.Error())
		c.HTML(http.StatusOK, "index.html", gin.H{"message": ""})
		return 
	}
	isOK, id := verifyToken(token)
	if !isOK{
		c.SetCookie("token", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
		return
	}

	isOK, filelist = listFiles(id)
	length := len(filelist)

	if !isOK{
		c.HTML(http.StatusInternalServerError, "home.html", gin.H{"message": "ServerError", "files":filelist, "length": length})
		return
	}
	c.HTML(http.StatusOK, "home.html", gin.H{"files": filelist, "length": length})
}


func logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/")
}


func main(){
	router := gin.Default()
	router.MaxMultipartMemory = SIZE

	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")

	router.GET("/ping", ping)
	router.GET("/about", func(c *gin.Context){c.HTML(http.StatusOK, "about.html", gin.H{})})
	router.GET("/logout", logout)

	router.GET("/", home)

	router.GET("/register", func(c *gin.Context){c.HTML(http.StatusOK, "register.html", gin.H{})})
	router.POST("/register", register)

	router.GET("/login", func(c *gin.Context){c.HTML(http.StatusOK, "login.html", gin.H{})})
	router.POST("/login", login)

	router.GET("/upload", func(c *gin.Context){
		token, err := c.Cookie("token")
		if err != nil {
			fmt.Println(err.Error())
			c.SetCookie("token", "", -1, "/", "", false, true)
			c.Redirect(http.StatusFound, "/")
			return
		}
		isOK, _ := verifyToken(token)
		if !isOK {
			c.SetCookie("token", "", -1, "/", "", false, true)
			c.Redirect(http.StatusFound, "/")
			return
		}
		c.HTML(http.StatusOK, "upload.html", gin.H{})
	})
	router.POST("/upload", upload)

	router.POST("/download", download)
	router.GET("/download", func(c *gin.Context){c.Redirect(http.StatusFound, "/")})
	router.POST("/delete", delete)
	router.GET("/delete", func(c *gin.Context){c.Redirect(http.StatusFound, "/")})
	router.Run("0.0.0.0:9909")
}