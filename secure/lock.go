package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"os"
	"path/filepath"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)


var config = mysql.Config{
	User:   os.Getenv("MYSQL_USER"),
	Passwd: os.Getenv("MYSQL_PASSWORD"),
	Net:    "tcp",
	Addr:   "database:3306",
	DBName: os.Getenv("MYSQL_DATABASE"),
}

type user struct {
	ID			string	 `json:"id"`
	Username	string	 `json:"username"`
	Password	string	 `json:"password"`
}

type fileData struct {
	FileHash	string	 `json:"hash"`
	FileName	string	 `json:"name"`
}

type JWTData struct {
	jwt.StandardClaims
	ID string `json:"id"`
}


func hashMD5(filePath multipart.File) (string, error) {
	var returnMD5String string
	hash := md5.New()
	if _, err := io.Copy(hash, filePath); err != nil {
		return returnMD5String, err
	}
	hashInBytes := hash.Sum(nil)[:16]
	returnMD5String = hex.EncodeToString(hashInBytes)
	return returnMD5String, nil
}


func encryptAES(savepath string, key []byte, id string, hash string) (string, error) {
	write_path := filepath.Join("/storage/", id, hash)
	if _, err := os.Stat(write_path); err == nil {
		return "file already exists", err
	}
	content, err := os.ReadFile(savepath)
	if err != nil {
		return "encryption error - tmp file read", err
	}
	aes_cipher, err := aes.NewCipher(key)
	if err != nil {
		return "encryption error - key", err
	}
	gcm, err := cipher.NewGCM(aes_cipher)
	if err != nil {
		return "encryption error - gcm", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "encryption error - nonce", err
	}
	enc := gcm.Seal(nonce, nonce, content, nil)
	err = ioutil.WriteFile(write_path, enc, 0666)
	if err != nil {
		return "encryption error - invalid ID", err
	}
	return "", nil
}


func decryptAES(readfile string, filename string, key []byte)(string, error){

	content, err := os.ReadFile(readfile)
	if err != nil {
		return "decryption error - unable to read file", err
	}
	aes_cipher, err := aes.NewCipher(key)
	if err != nil {
		return "decryption error - key", err
	}
	gcm, err := cipher.NewGCM(aes_cipher)
	if err != nil {
		return "decryption error - gcm", err
	}

	nonceSize := gcm.NonceSize()
	if len(content) < nonceSize {
		return "decryption error - file corrupted", err
	}

	nonce, ciphertext := content[:nonceSize], content[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return "Incorrect Password", err
	}
	write_path := filepath.Join("/tmp/", filename)
	err = ioutil.WriteFile(write_path, plaintext, 0666)

	if err != nil {
		return "decryption error - tmp file save", err
	}
	return "", nil
}


func usernameExists(username string) (bool, string) {
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		fmt.Println(err.Error())
		return true, "Server Error"
	}
	defer db.Close()

	var res user

	result := db.QueryRow("SELECT * from users WHERE username=?", username)
	err = result.Scan(&res.ID, &res.Username, &res.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, ""
		}
		fmt.Println(err.Error())
		return true, "Server error"
	}
	return true, "user already exists"
}


func registerUser(id string, username string, password string) (string) {
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		fmt.Println(err.Error())
		return "Server Error"
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", id, username, password)
	if err != nil {
		fmt.Println(err.Error())
		return "Error in registering user"
	}
	_, err = db.Exec("CREATE TABLE `" + id + "` (`hash` varchar(32) NOT NULL,`name` varchar(100) NOT NULL, PRIMARY KEY (`hash`))")
	if err != nil {
		fmt.Println(err.Error())
		db.Exec("DELETE FROM users WHERE id=?", id)
		return "Error in registering user"
	}
	return ""
}


func validateUser(username string, password string) (bool, string) {
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		fmt.Println(err.Error())
		return false, "Server Error"
	}
	defer db.Close()

	var res user

	result := db.QueryRow("SELECT * from users WHERE username=? AND password=?", username, password)
	err = result.Scan(&res.ID, &res.Username, &res.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "Incorrect credentials"
		}
		fmt.Println(err.Error())
		return false, "Server Error"
	}
	return true, res.ID

}


func validateID(id string) (bool, string) {
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		fmt.Println(err.Error())
		return false, "Server Error"
	}
	defer db.Close()

	var res user
	result := db.QueryRow("SELECT * from users WHERE id=?", id)
	err = result.Scan(&res.ID, &res.Username, &res.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "unauthorized"
		}
		fmt.Println(err.Error())
		return false, "Server Error"
	}
	return true, id
}


func updateTable(id string, hash string, name string, action string) (string) {
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		fmt.Println(err.Error())
		return "Server Error"
	}
	defer db.Close()

	if action == "insert" {
		_, err = db.Exec("INSERT INTO `" + id + "` (hash, name) VALUES (?, ?)", hash, name)
		if err != nil {
			fmt.Println(err.Error())
			return "Error in updating table"
		}
	} else {
		_, err = db.Exec("DELETE FROM `" + id + "` WHERE hash=?", hash)
		if err != nil {
			fmt.Println(err.Error())
			return "Error in updating table"
		}
	}
	return ""
}


func generateKey() {
	random_string := make([]byte, 16)
	_, _ = rand.Read(random_string)
	hash := SHA256Hash(string((random_string)))
	os.Setenv("SECRET_KEY", hash)
}


func generateToken(id string) (string, string) {
	key := os.Getenv("SECRET_KEY")
	if key == "" {
		generateKey()
		key = os.Getenv("SECRET_KEY")
	}
	claims := JWTData{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Minute * 30).Unix(),
			},
			ID: id,
		}

		tokenString := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token, err := tokenString.SignedString([]byte(key))
		if err != nil {
			fmt.Println(err.Error())
			return "", "Server Error"
		}

		return token, ""
}


func verifyToken(token string) (bool, string) {
	key := os.Getenv("SECRET_KEY")
	if key == "" {
		generateKey()
		key = os.Getenv("SECRET_KEY")
		return false, "unauthorized"
	}

	claims := &JWTData{}

	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(key), nil
	})

	if err != nil {
		fmt.Println(err.Error())
		return false, "unauthorized"
	}

	id := claims.ID
	if id == ""{
		return false, "unauthorized"
	}

	return validateID(id)
}


func checkFile(hash string, id string) (bool, string, string) {
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		fmt.Println(err.Error())
		return true, "Server Error", ""
	}
	defer db.Close()

	var res fileData

	result := db.QueryRow("SELECT * from `" + id + "` WHERE hash=?", hash)
	err = result.Scan(&res.FileHash, &res.FileName)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "File does not exist", ""
		}
		fmt.Println(err.Error())
		return true, "Server Error", ""
	}
	return true, "file already exists", res.FileName
}


func listFiles(id string) (bool, []fileData) {

	var filelist []fileData

	db, err := sql.Open("mysql", config.FormatDSN())

	if err != nil {
		fmt.Println(err.Error())
		return false, filelist
	}
	defer db.Close()

	result, err := db.Query("SELECT * from `" + id + "`")
	if err != nil {
		if err == sql.ErrNoRows {
			return true, filelist
		}
		fmt.Println(err.Error())
		return false, filelist
	}

	for result.Next() {
		var tag fileData
		err = result.Scan(&tag.FileHash, &tag.FileName)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		filelist = append(filelist, tag)
	}
	return true, filelist
}


func getUUID() string {
	id := uuid.New()
	return id.String()
}


func hashPass(password string) string {
	return SHA256Hash(MD5Hash(password))
}


func MD5Hash(payload string) string {
	obj := md5.New()
	obj.Write([]byte(payload))
	return hex.EncodeToString(obj.Sum(nil))
}


func SHA256Hash(payload string) string {
	obj := sha256.New()
	obj.Write([]byte(payload))
	return hex.EncodeToString(obj.Sum(nil))
}
