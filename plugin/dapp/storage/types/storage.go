package types

import (
	"github.com/33cn/chain33/types"

	"reflect"
)

/*
 * 交易相关类型定义
 * 交易action通常有对应的log结构，用于交易回执日志记录
 * 每一种action和log需要用id数值和name名称加以区分
 */

// action类型id和name，这些常量可以自定义修改
const (
	TyUnknowAction = iota
	TyContentStorageAction
	TyHashStorageAction
	TyLinkStorageAction
	TyEncryptStorageAction
	TyEncryptShareStorageAction

	NameContentStorageAction      = "ContentStorage"
	NameHashStorageAction         = "HashStorage"
	NameLinkStorageAction         = "LinkStorage"
	NameEncryptStorageAction      = "EncryptStorage"
	NameEncryptShareStorageAction = "EncryptShareStorage"

	FuncNameQueryStorage      = "QueryStorage"
	FuncNameBatchQueryStorage = "BatchQueryStorage"
)

// log类型id值
const (
	TyUnknownLog = iota
	TyContentStorageLog
	TyHashStorageLog
	TyLinkStorageLog
	TyEncryptStorageLog
	TyEncryptShareStorageLog
)

var (
	//StorageX 执行器名称定义
	StorageX = "storage"
	//定义actionMap
	actionMap = map[string]int32{
		NameContentStorageAction:      TyContentStorageAction,
		NameHashStorageAction:         TyHashStorageAction,
		NameLinkStorageAction:         TyLinkStorageAction,
		NameEncryptStorageAction:      TyEncryptStorageAction,
		NameEncryptShareStorageAction: TyEncryptShareStorageAction,
	}
	//定义log的id和具体log类型及名称，填入具体自定义log类型
	logMap = map[int64]*types.LogInfo{
		TyContentStorageLog:      {Ty: reflect.TypeOf(ReceiptStorage{}), Name: "LogContentStorage"},
		TyHashStorageLog:         {Ty: reflect.TypeOf(ReceiptStorage{}), Name: "LogHashStorage"},
		TyLinkStorageLog:         {Ty: reflect.TypeOf(ReceiptStorage{}), Name: "LogLinkStorage"},
		TyEncryptStorageLog:      {Ty: reflect.TypeOf(ReceiptStorage{}), Name: "LogEncryptStorage"},
		TyEncryptShareStorageLog: {Ty: reflect.TypeOf(ReceiptStorage{}), Name: "LogEncryptShareStorage"},
	}
)

// init defines a register function
func init() {
	types.AllowUserExec = append(types.AllowUserExec, []byte(StorageX))
	//注册合约启用高度
	types.RegFork(StorageX, InitFork)
	types.RegExec(StorageX, InitExecutor)
}

// InitFork defines register fork
func InitFork(cfg *types.Chain33Config) {
	cfg.RegisterDappFork(StorageX, "Enable", 0)
}

// InitExecutor defines register executor
func InitExecutor(cfg *types.Chain33Config) {
	types.RegistorExecutor(StorageX, NewType(cfg))
}

type StorageType struct {
	types.ExecTypeBase
}

func NewType(cfg *types.Chain33Config) *StorageType {
	c := &StorageType{}
	c.SetChild(c)
	c.SetConfig(cfg)
	return c
}

// GetPayload 获取合约action结构
func (s *StorageType) GetPayload() types.Message {
	return &StorageAction{}
}

// GeTypeMap 获取合约action的id和name信息
func (s *StorageType) GetTypeMap() map[string]int32 {
	return actionMap
}

// GetLogMap 获取合约log相关信息
func (s *StorageType) GetLogMap() map[int64]*types.LogInfo {
	return logMap
}
