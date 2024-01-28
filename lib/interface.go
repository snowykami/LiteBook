package lib

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var UserDB *gorm.DB
var BookDB *gorm.DB
var TokenValidTime = time.Minute * 15
var RefreshTokenValidTime = time.Hour * 24 * 15

var AConfig Config

// 1.用户相关

// Register 注册
func Register(c *gin.Context) {
	// 注册 username password
	// 防止傻逼分不清params和form
	username := c.PostForm("username")
	password := c.PostForm("password")

	// 先查询用户是否被注册
	// 如果被注册，返回错误信息
	// 如果没有被注册，验证用户名合法性
	if !VerifyUsername(username) {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusParamValueInvalid,
			"info":   "username illegal, username can only contain letters, numbers and underscores, and the length is 4-16",
			"data": gin.H{
				"username": username,
			},
		})
		return
	}
	var user User
	UserDB.Where("username = ?", username).First(&user)
	if user.Username != "" {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserAlreadyExist,
			"info":   "username already exists",
		})
	} else {
		// 创建用户
		userId := GenerateUserId()
		UserDB.Create(&User{
			ID:       userId,
			Username: username,
			Password: HashPassword(password),
		})

		c.JSON(http.StatusOK, gin.H{
			"status": StatusSuccess,
			"info":   "success",
			"data": gin.H{
				"username": username,
				"user_id":  userId,
			},
		})
	}
}

// UserToken 登录获取token
func UserToken(c *gin.Context) {
	// 登录获取token
	// 获取get参数
	username := c.Query("username")
	password := c.Query("password")
	// 用户名或密码为空
	if username == "" || password == "" {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusParamValueMissing,
			"info":   "username or password is missing",
		})
		return
	}

	// 查询用户判断用户是否存在
	user, err := GetUserByUsername(username)
	if err != nil {
		// 用户不存在
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}

	// 验证密码
	if HashPassword(password) != user.Password {
		// 密码错误
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserPasswordError,
			"info":   "password is incorrect",
		})
	} else {
		// 生成token
		secretKey := GenerateSecretKey()
		token := GenerateToken(user.ID, secretKey, TokenValidTime)
		refreshToken := GenerateToken(user.ID, secretKey, RefreshTokenValidTime)
		// 更新验证信息
		EditUserAttr(user.ID, "secret_key", secretKey)
		EditUserAttr(user.ID, "token", token)
		EditUserAttr(user.ID, "refresh_token", refreshToken)
		c.JSON(http.StatusOK, gin.H{
			"status": StatusSuccess,
			"info":   "success",
			"data": gin.H{
				"token":         token,
				"refresh_token": refreshToken,
			},
		})
	}

}

// UserTokenRefresh 刷新token
func UserTokenRefresh(c *gin.Context) {
	// 刷新token
	// 从请求头获取Authorization
	authorization := c.GetHeader("Authorization")
	// 从get参数获取refresh_token
	refreshToken := c.Query("refresh_token")
	// 查询用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 验证refresh_token，无效需要重新登录
	verifyResult, StatusCode, StatusMessage := VerifyToken(refreshToken, "refresh_token")
	if !verifyResult {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusCode,
			"info":   StatusMessage,
		})
		return
	}
	// 生成新的token和refresh_token
	secretKey := GenerateSecretKey()
	token := GenerateToken(user.ID, secretKey, TokenValidTime)
	refreshToken = GenerateToken(user.ID, secretKey, RefreshTokenValidTime)
	// 更新用户token
	EditUserAttr(user.ID, "secret_key", secretKey)
	EditUserAttr(user.ID, "token", token)
	EditUserAttr(user.ID, "refresh_token", refreshToken)
	c.JSON(
		http.StatusOK,
		gin.H{
			"status": StatusSuccess,
			"info":   "success",
			"data": gin.H{
				"token":         token,
				"refresh_token": refreshToken,
			},
		})
}

// UserPassword 修改密码
func UserPassword(c *gin.Context) {
	// GET
	// 获取Authorization请求头
	authorization := c.GetHeader("Authorization")
	// 获取put参数
	oldPassword := c.PostForm("old_password")
	newPassword := c.PostForm("new_password")
	// 验证token
	verifyResult, StatusCode, StatusMessage := VerifyToken(authorization, "token")
	if !verifyResult {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusCode,
			"info":   StatusMessage,
		})
		return
	}
	// 获取用户密钥，先查询有无用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 验证密码
	log.Println(oldPassword, newPassword)
	if HashPassword(oldPassword) != user.Password {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserPasswordError,
			"info":   "password is incorrect",
		})
		return
	}
	// 修改密码
	EditUserAttr(user.ID, "password", HashPassword(newPassword))
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
	})
}

// UserInfo 获取用户信息
func UserInfo(c *gin.Context) {
	// 获取用户信息
	// 获取用户id
	userId, err := strconv.Atoi(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user id illegal",
		})
		return
	}
	// 查询用户
	user, err := GetUserById(userId)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 返回用户信息
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
		"data": gin.H{
			"user": gin.H{
				"id":           user.ID,
				"avatar":       "{" + user.Info.Avatar + "}",
				"nickname":     user.Info.Nickname,
				"introduction": user.Info.Introduction,
				"phone":        user.Info.Phone,
				"qq":           user.Info.QQ,
				"gender":       user.Info.Gender,
				"email":        user.Info.Email,
				"birthday":     user.Info.Birthday,
			},
		},
	})
}

// UserInfoEdit 修改用户信息
func UserInfoEdit(c *gin.Context) {
	// 修改用户信息
	// 获取Authorization请求头
	authorization := c.GetHeader("Authorization")
	// 验证token
	verifyResult, StatusCode, StatusMessage := VerifyToken(authorization, "token")
	if !verifyResult {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusCode,
			"info":   StatusMessage,
		})
		return
	}
	// 查询用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 获取所有postform参数
	avatar := c.PostForm("avatar")
	nickname := c.PostForm("nickname")
	introduction := c.PostForm("introduction")
	email := c.PostForm("email")
	gender := c.PostForm("gender")
	birthday := c.PostForm("birthday")

	phone := c.PostForm("phone")
	qq := c.PostForm("qq")
	// 先判断是否为空
	var phone_int int
	var qq_int int
	var err1 error
	var err2 error
	if phone == "" {
		phone_int = 0
	} else {
		phone_int, err1 = strconv.Atoi(phone)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"status": StatusParamValueInvalid,
				"info":   "param value invalid",
			})
			return
		}
	}
	if qq == "" {
		qq_int = 0
	} else {
		qq_int, err2 = strconv.Atoi(qq)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"status": StatusParamValueInvalid,
				"info":   "param value invalid",
			})
			return
		}
	}

	if err1 != nil || err2 != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusParamValueInvalid,
			"info":   "param value invalid",
		})
		return
	}

	// 修改用户信息，禁止修改密钥和令牌字段
	userInfo := Info{
		Avatar:       avatar,
		Nickname:     nickname,
		Introduction: introduction,
		Email:        email,
		QQ:           qq_int,
		Phone:        phone_int,
		Gender:       gender,
		Birthday:     birthday,
	}
	EditUserInfo(user.ID, userInfo)
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
		"data":   userInfo,
	})
}

// 书籍相关

func BookList(c *gin.Context) {
	// 获取书籍列表，返回{data:{books:[]}}
	var bookList []Book
	BookDB.Find(&bookList)
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
		"data": gin.H{
			"books": bookList,
		},
	})
}

func BookSearch(c *gin.Context) {
	// 搜索书籍
	//authorization := c.GetHeader("Authorization")
	// token仅用于识别用户，不需要验证
	//user := GetUserByToken(authorization)

	bookName := c.Query("book_name")
	// bookName为关键词，模糊搜索
	var bookList []Book
	BookDB.Where("name LIKE ?", "%"+bookName+"%").Find(&bookList)
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
		"data": gin.H{
			"books": bookList,
		},
	})

}

func BookStar(c *gin.Context) {
	// 收藏书籍
	// 获取authorization
	authorization := c.GetHeader("Authorization")
	vR, sC, sM := VerifyToken(authorization, "token")
	if !vR {
		c.JSON(http.StatusOK, gin.H{
			"status": sC,
			"info":   sM,
		})
		return
	}
	// 获取post参数
	bookId := c.PostForm("book_id")
	// 查询用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 查询书籍
	var book Book
	BookDB.Where("id = ?", bookId).First(&book)
	if book.ID == 0 {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusParamValueInvalid,
			"info":   "param value invalid",
		})
		return
	}
	// 判断是否已经收藏
	for _, v := range user.StaredBooks {
		if v == book {
			c.JSON(http.StatusOK, gin.H{
				"status": StatusSuccess,
				"info":   "success",
			})
			return
		}
	}
	// 收藏书籍
	user.StaredBooks = append(user.StaredBooks, book)
	EditUserAttr(user.ID, "stared_books", user.StaredBooks)
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
	})
}

func BookLabel(c *gin.Context) {
	// 获取相应标签的书籍列表
	// 获取get参数
	label := c.Query("label")
	// 查询书籍
	var bookList []Book
	BookDB.Where("label = ?", label).Find(&bookList)
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
		"data": gin.H{
			"books": bookList,
		},
	})
}

// 评论相关

func GetComment(c *gin.Context) {
	// 获取某本书下所有评论
	bookId := c.Param("book_id")
	var commentList []Comment
	BookDB.Where("book_id = ?", bookId).Find(&commentList)
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
		"data": gin.H{
			"comments": commentList,
		},
	})
}

func PostComment(c *gin.Context) {
	// 发表评论
	// 获取authorization
	authorization := c.GetHeader("Authorization")
	vR, sC, sM := VerifyToken(authorization, "token")
	if !vR {
		c.JSON(http.StatusOK, gin.H{
			"status": sC,
			"info":   sM,
		})
		return
	}
	// 获取post参数
	bookId := c.Param("book_id")
	content := c.PostForm("content")
	// 查询用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 查询书籍
	var book Book
	BookDB.Where("id = ?", bookId).First(&book)
	if book.ID == 0 {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusParamValueInvalid,
			"info":   "param value invalid",
		})
		return
	}
	// 创建评论
	// 评论时间
	publishTime := time.Now().Format("2006-01-02 15:04:05")
	// 评论id
	// 评论
	comment := Comment{
		BookID:      bookId,
		PublishTime: publishTime,
		Content:     content,
		UserId:      user.ID,
		Avatar:      user.Info.Avatar,
		Nickname:    user.Info.Nickname,
		PraiseCount: 0,
	}
	BookDB.Create(&comment)

}

func DeleteComment(c *gin.Context) {
	// 删除评论，仅能删除自己的
	// 获取authorization
	authorization := c.GetHeader("Authorization")
	vR, sC, sM := VerifyToken(authorization, "token")
	if !vR {
		c.JSON(http.StatusOK, gin.H{
			"status": sC,
			"info":   sM,
		})
		return
	}
	// 获取post参数
	commentId := c.Param("comment_id")
	// 查询用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 查询评论
	var comment Comment
	BookDB.Where("id = ?", commentId).First(&comment)
	if comment.ID == 0 {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusParamValueInvalid,
			"info":   "param value invalid",
		})
		return
	}
	// 判断是否为自己的评论
	if comment.UserId != user.ID {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserPermissionError,
			"info":   "user permission error",
		})
		return
	}
	// 删除评论
	BookDB.Delete(&comment)
}

func PutComment(c *gin.Context) {
	// 修改更新评论
	// 获取authorization
	authorization := c.GetHeader("Authorization")
	vR, sC, sM := VerifyToken(authorization, "token")
	if !vR {
		c.JSON(http.StatusOK, gin.H{
			"status": sC,
			"info":   sM,
		})
		return
	}
	// 获取post参数
	commentId := c.Param("comment_id")
	content := c.PostForm("content")
	// 查询用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 查询评论
	var comment Comment
	BookDB.Where("id = ?", commentId).First(&comment)
	if comment.ID == 0 {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusParamValueInvalid,
			"info":   "param value invalid",
		})
		return
	}
	// 判断是否为自己的评论
	if comment.UserId != user.ID {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserPermissionError,
			"info":   "user permission error",
		})
		return
	}
	// 修改评论
	BookDB.Model(&comment).Update("content", content)
}

// Operate 操作相关

// OperatePraise 点赞
func OperatePraise(c *gin.Context) {
	authorization := c.GetHeader("Authorization")
	// 三参数验证
	vR, sC, sM := VerifyToken(authorization, "token")
	if !vR {
		c.JSON(http.StatusOK, gin.H{
			"status": sC,
			"info":   sM,
		})
		return
	}
	// 获取post参数
	// 被点赞类型
	model := c.PostForm("model")
	// 被点赞对象id
	targetId := c.PostForm("target_id")
	// 查询用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 查询被点赞对象,1为帖子,2为评论
	switch model {
	case "1":
		var comment Comment
		BookDB.Where("id = ?", targetId).First(&comment)
		if comment.ID == 0 {
			c.JSON(http.StatusOK, gin.H{
				"status": StatusParamValueInvalid,
				"info":   "param value invalid",
			})
			return
		}
		PraiseComment(comment.PostID, user.ID)

	case "2":
		var comment Comment
		BookDB.Where("id = ?", targetId).First(&comment)
		if comment.ID == 0 {
			c.JSON(http.StatusOK, gin.H{
				"status": StatusParamValueInvalid,
				"info":   "param value invalid",
			})
			return
		}
		PraiseComment(comment.PostID, user.ID)
	}

	// 查询评论
}

func OperateCollectList(c *gin.Context) {
	// 获取authorization
	authorization := c.GetHeader("Authorization")
	vR, sC, sM := VerifyToken(authorization, "token")
	if !vR {
		c.JSON(http.StatusOK, gin.H{
			"status": sC,
			"info":   sM,
		})
		return
	}
	// 查询用户
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 查询用户收藏列表
	var bookList []Book
	BookDB.Where("id IN ?", user.StaredBooks).Find(&bookList)
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
		"data": gin.H{
			"collections": bookList,
		},
	})

}

func OperateFocus(c *gin.Context) {
	// 关注用户
	// 获取authorization
	authorization := c.GetHeader("Authorization")
	vR, sC, sM := VerifyToken(authorization, "token")
	if !vR {
		c.JSON(http.StatusOK, gin.H{
			"status": sC,
			"info":   sM,
		})
		return
	}
	// 获取post参数
	focusedUserId, err := strconv.Atoi(c.PostForm("user_id"))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusParamValueInvalid,
			"info":   "param value invalid",
		})
		return
	}
	// 查询用户

	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 查询被关注用户
	focusedUser, err := GetUserById(focusedUserId)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "focused user not found",
		})
		return
	}
	// 修改用户
	user.FocusedUsers = append(user.FocusedUsers, focusedUser)
	UserDB.Save(&user)
}

// 附加功能

func BookAdd(c *gin.Context) {
	// 验证token

	authorization := c.GetHeader("Authorization")
	verifyResult, StatusCode, StatusMessage := VerifyToken(authorization, "token")
	if !verifyResult {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusCode,
			"info":   StatusMessage,
		})
		return
	}
	user, err := GetUserByToken(authorization)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserNotFound,
			"info":   "user not found",
		})
		return
	}
	// 用户id在管理员列表中
	log.Println(user.ID, AConfig.Admin)
	if !In(user.ID, AConfig.Admin) {
		c.JSON(http.StatusOK, gin.H{
			"status": StatusUserPermissionError,
			"info":   "user permission error",
		})
		return
	}
	// 获取所有postform参数
	var book Book
	err = c.Bind(&book)
	if err != nil {
		return
	}
	BookDB.Create(&book)
	c.JSON(http.StatusOK, gin.H{
		"status": StatusSuccess,
		"info":   "success",
		"data":   book,
	})

}

// 内部函数

func EditUserInfo(userID int, info Info) {
	// 仅修User.Info改给定的字段
	var user User
	UserDB.Where("id = ?", userID).First(&user)
	UserDB.Model(&user).Updates(info)
}

func EditUserAttr(userID int, attr string, value interface{}) {
	// 修改用户属性
	var user User
	UserDB.Where("id = ?", userID).First(&user)
	UserDB.Model(&user).Update(attr, value)
}

func GenerateSecretKey() string {
	// Generate a random 32 byte key string
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(key)
}

func GenerateToken(userId int, secretKey string, validTime time.Duration) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(validTime).Unix()
	claims["iat"] = time.Now().Unix()
	claims["sub"] = userId

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return ""
	}

	return tokenString
}

func GenerateUserId() int {
	// 生成用户ID,从100000000开始
	var user User
	UserDB.Last(&user)
	if user.ID >= 100000000 {
		return user.ID + 1
	} else {
		return 100000000
	}
}

func GetUserById(userId int) (User, error) {
	// 通过用户ID获取用户
	var user User
	UserDB.Where("id = ?", userId).First(&user)
	if user.Username == "" {
		return User{}, UserNotFoundError{UserId: userId}
	}
	return user, nil
}

func GetUserByUsername(username string) (User, error) {
	// 通过用户名获取用户
	var user User
	UserDB.Where("username = ?", username).First(&user)
	if user.Username == "" {
		return User{}, UserNotFoundError{Username: username}
	}
	return user, nil
}

func GetUserByToken(token string) (User, error) {
	// 通过Token获取用户
	var user User
	UserDB.Where("token = ?", token).First(&user)
	if user.Username == "" {
		return User{}, UserNotFoundError{UserToken: token}
	}
	return user, nil
}

func HashPassword(password string) string {
	// 将密码进行哈希，不加盐
	hash := sha256.New()
	hash.Write([]byte(password))
	hashedPassword := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return hashedPassword
}

func In(target int, strArray []int) bool {
	for _, element := range strArray {
		if target == element {
			return true
		}
	}
	return false
}

func InitDatabase(config Config) {
	// 初始化数据库，从配置文件中读取数据库配置，DEV模式输出日志，PROD模式不输出日志
	// 检测data文件夹是否存在，不存在则创建
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		err := os.Mkdir("data", os.ModePerm)
		if err != nil {
			log.Fatal("Failed to create data folder")
		}
	}

	// 初始化用户数据库
	mode := config.Mode
	var err error
	if mode == "DEV" {
		UserDB, err = gorm.Open(sqlite.Open(config.DatabaseConfig.UserDB), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	} else {
		UserDB, err = gorm.Open(sqlite.Open(config.DatabaseConfig.UserDB))
	}
	if err != nil {
		log.Fatal("Failed to connect to user database")
	}
	err = UserDB.AutoMigrate(User{})
	if err != nil {
		log.Fatal("Failed to create User table")
	}

	// 初始化书籍数据库
	if mode == "DEV" {
		BookDB, err = gorm.Open(sqlite.Open(config.DatabaseConfig.BookDB), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	} else {
		BookDB, err = gorm.Open(sqlite.Open(config.DatabaseConfig.BookDB))
	}
	if err != nil {
		log.Fatal("Failed to connect to book database")
	}
	err = BookDB.AutoMigrate(Book{}, Comment{})
	if err != nil {
		log.Fatal("Failed to create Book table")
	}
}

func PraiseComment(commentId int, userId int) {
	// 点赞评论
	// 查询评论
	var comment Comment
	BookDB.Where("id = ?", commentId).First(&comment)
	if comment.ID == 0 {
		return
	}
	// 查询用户
	var user User
	UserDB.Where("id = ?", userId).First(&user)
	if user.ID == 0 {
		return
	}
	// 修改评论
	comment.PraiseCount += 1
	BookDB.Save(&comment)
	// 修改用户
	user.PrisedComments = append(user.PrisedComments, comment)
	UserDB.Save(&user)
}

func ReadConfig(config *Config) {
	// 先检测是否有配置文件
	if _, err := os.Stat("config.yml"); os.IsNotExist(err) {
		// 不存在配置文件，创建默认配置文件
		defaultConfig := Config{
			Port: 8080,
			Host: "127.0.0.1",
			Mode: "PROD",
			DatabaseConfig: DatabaseConfig{
				UserDB: "data/user.db",
				BookDB: "data/book.db",
			},
		}

		// 将默认配置写入到文件

		file, err := os.Create("config.yml")
		if err != nil {
			log.Fatal("Failed to create config file")
		}

		newEncoder := yaml.NewEncoder(file)

		err = newEncoder.Encode(defaultConfig)
		if err != nil {
			log.Fatal("Failed to encode default config")
		}

	}
	// 存在配置文件，读取配置文件
	file, err := os.Open("config.yml")
	if err != nil {
		log.Fatal("Failed to open config file")
	}
	// 解码配置文件
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		log.Fatal("Failed to decode config file")
	}
}

func VerifyToken(token string, tokenType string) (bool, int, string) {
	// 验证Token有效性
	// tokenType为"token"或"refresh_token"
	// 先找到对应的用户，用户不存在则返回false
	var user User
	if tokenType == "token" {
		UserDB.Where("token = ?", token).First(&user)
	} else if tokenType == "refresh_token" {
		UserDB.Where("refresh_token = ?", token).First(&user)
	} else {
		return false, StatusUserTokenError, "token type illegal"
	}
	if user.Username == "" {
		return false, StatusUserNotFound, "user not found by token"
	}

	// 用用户密钥解析Token
	secretKey := user.SecretKey

	// 解析 JWT 令牌为json
	parsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// 在实际应用中，你可能需要提供用于验证签名的密钥
		return []byte(secretKey), nil
	})

	// 处理解析错误
	//if err != nil {
	//	return false, StatusUserTokenError, "token parse error"
	//}

	// 获取过期时间（exp）
	expirationTime, ok := parsedToken.Claims.(jwt.MapClaims)["exp"].(float64)
	if !ok {
		if tokenType == "token" {
			return false, StatusUserTokenExpired, "token expired, please refresh token"
		} else {
			return false, StatusUserTokenRefreshExpired, "refresh token expired, please login again"
		}
	}

	// 检查是否已过期
	if int64(expirationTime) < time.Now().Unix() {
		if tokenType == "token" {
			return false, StatusUserTokenExpired, "token expired, please refresh token"
		} else {
			return false, StatusUserTokenRefreshExpired, "refresh token expired, please login again"
		}
	}

	// 验证通过
	return true, StatusSuccess, "success"
}

func VerifyUsername(username string) bool {
	// 验证用户名合法性，仅能包含大小写字母、数字、下划线，且长度为4-16位，是否重复由数据库判断
	// 先查询数据库
	var user User
	if user.Username != "" {
		log.Println(1)
		return false
	}
	if len(username) < 4 || len(username) > 16 {
		return false
	}
	for _, char := range username {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}
	return true
}
