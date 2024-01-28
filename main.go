// Author: SnowyKami
// 仅用于红岩后端开发部作业，稳定性并未进行测试

package main

import (
	"Lite/lib"
	"github.com/gin-gonic/gin"
	"strconv"
)

func main() {
	router := gin.Default()
	// 1.用户相关
	// 注册
	router.POST("/register", lib.Register)
	// 登录 获取token
	router.GET("/user/token", lib.UserToken)
	// 刷新token
	router.GET("/user/token/refresh", lib.UserTokenRefresh)
	// 修改密码
	router.PUT("/user/password", lib.UserPassword)
	// 获取用户信息
	router.GET("/user/info/:user_id", lib.UserInfo)
	// 修改用户信息
	router.PUT("/user/info", lib.UserInfoEdit)

	// 2.书籍相关
	// 获取书籍列表
	router.GET("/book/list", lib.BookList)
	// 搜索书籍
	router.GET("/book/search", lib.BookSearch)
	// 收藏书籍
	router.PUT("/book/star", lib.BookStar)
	// 获取相应标签的书籍列表
	router.GET("/book/label", lib.BookLabel)

	// 3.评论相关
	// 获取某本书下所有评论
	router.GET("/comment/:book_id", lib.GetComment)
	// 发表评论
	router.POST("/comment/:book_id", lib.PostComment)
	// 删除评论
	router.DELETE("/comment/:comment_id", lib.DeleteComment)
	// 修改更新评论
	router.PUT("/comment/:comment_id", lib.PutComment)

	// 4.操作相关
	// 点赞
	router.PUT("/operate/praise", lib.OperatePraise)
	// 获取用户收藏列表
	router.GET("/operate/collect/list", lib.OperateCollectList)
	// 关注用户
	router.PUT("/operate/focus", lib.OperateFocus)

	// 5.附加功能
	router.PUT("/book/add", lib.BookAdd)

	// 读取配置文件
	// 初始化数据库
	lib.ReadConfig(&lib.AConfig)
	lib.InitDatabase(lib.AConfig)

	// 运行
	err := router.Run(lib.AConfig.Host + ":" + strconv.Itoa(lib.AConfig.Port))
	if err != nil {
		return
	}
}
