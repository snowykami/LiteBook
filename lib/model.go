package lib

import (
	"gorm.io/gorm"
)

type Comment struct {
	gorm.Model
	PostID      int    `json:"post_id" gorm:"primaryKey"`
	BookID      string `json:"book_id"`
	PublishTime string `json:"publish_time"`
	Content     string `json:"content"`
	UserId      int    `json:"user_id"`
	Avatar      string `json:"avatar"`
	Nickname    string `json:"nickname"`
	PraiseCount int    `json:"praise_count"`
	IsPraised   bool   `json:"is_praised"`
	IsFocus     bool   `json:"is_focus"`
}

type Book struct {
	gorm.Model
	ID          int    `json:"book_id" gorm:"primaryKey"`
	Name        string `json:"name"`
	IsStar      bool   `json:"is_star"`
	Author      string `json:"author"`
	CommentNum  int    `json:"comment_num"`
	Score       int    `json:"score"`
	Cover       string `json:"cover"`
	PublishTime string `json:"publish_time"`
	Link        string `json:"link"`
	Label       string `json:"label"`
}

type User struct {
	gorm.Model
	ID             int       `json:"id" gorm:"primaryKey"`
	Username       string    `json:"username"`
	Password       string    `json:"password"`
	SecretKey      string    `json:"secret_key"`
	Token          string    `json:"token"`
	RefreshToken   string    `json:"refresh_token"`
	Info           Info      `json:"info" gorm:"embedded"`
	StaredBooks    []Book    `json:"stared_books" gorm:"many2many"`
	PrisedPosts    []Comment `json:"prised_posts" gorm:"many2many"`
	PrisedComments []Comment `json:"prised_comments" gorm:"many2many"`
	FocusedUsers   []User    `json:"focused_users" gorm:"many2many"`
}

type Info struct {
	Gender       string `json:"gender"`
	Nickname     string `json:"nickname"`
	QQ           int    `json:"qq"`
	Birthday     string `json:"birthday"`
	Email        string `json:"email"`
	Avatar       string `json:"avatar"`
	Introduction string `json:"introduction"`
	Phone        int    `json:"phone"`
}

type Config struct {
	Port int    `yaml:"port"`
	Host string `yaml:"host"`

	// DEV/PROD
	Mode           string         `yaml:"mode"`
	Admin          []int          `yaml:"admin"`
	DatabaseConfig DatabaseConfig `yaml:"database"`
}

type DatabaseConfig struct {
	UserDB string `yaml:"user"`
	BookDB string `yaml:"book"`
}
