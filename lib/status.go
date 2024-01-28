package lib

const (
	// StatusSuccess 一般用于成功，其他都是失败
	StatusSuccess = 10000
	// StatusParamError 参数错误
	StatusParamError = 10001
	// StatusParamMissing 缺少参数
	StatusParamMissing = 10002
	// StatusParamInvalid 参数无效
	StatusParamInvalid = 10003
	// StatusParamTypeInvalid 参数类型无效
	StatusParamTypeInvalid = 10004
	// StatusParamValueInvalid 参数值无效
	StatusParamValueInvalid = 10005
	// StatusParamValueMissing 参数值缺失
	StatusParamValueMissing = 10006

	// StatusUserError 用户相关错误
	StatusUserError = 20000
	// StatusUserNotFound 用户不存在
	StatusUserNotFound = 20001
	// StatusUserAlreadyExist 用户已存在
	StatusUserAlreadyExist = 20002
	// StatusUserPasswordError 密码错误
	StatusUserPasswordError = 20003

	// StatusUserTokenError token错误
	StatusUserTokenError = 20004
	// StatusUserTokenExpired token过期
	StatusUserTokenExpired = 20005
	// StatusUserTokenInvalid token无效
	StatusUserTokenInvalid = 20006
	// StatusUserTokenMissing token缺失
	StatusUserTokenMissing = 20007
	// StatusUserTokenRefreshError 刷新token错误
	StatusUserTokenRefreshError = 20008
	// StatusUserTokenRefreshExpired 刷新token过期
	StatusUserTokenRefreshExpired = 20009
	// StatusUserTokenRefreshInvalid 刷新token无效
	StatusUserTokenRefreshInvalid = 20010
	// StatusUserTokenRefreshMissing 刷新token缺失
	StatusUserTokenRefreshMissing = 20011
	// StatusUserPasswordSame 密码相同
	StatusUserPasswordSame = 20012
	// StatusUserPasswordInvalid 密码无效
	StatusUserPasswordInvalid = 20013
	// StatusUserPasswordMissing 密码缺失
	StatusUserPasswordMissing = 20014
	// StatusUserPasswordNotMatch 密码不匹配
	StatusUserPasswordNotMatch = 20015
	// StatusUserPasswordNotSame 密码不相同
	StatusUserPasswordNotSame = 20016

	StatusUserPermissionError = 20017
)
