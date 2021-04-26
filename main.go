// Small Authentication
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c-bata/go-prompt"
	"golang.org/x/crypto/sha3"
	"golang.org/x/term"
)

const (
	modeGuest      = 0
	modeUser       = 1
	expireDuration = time.Minute * 3
)

var (
	errAccExisted error = errors.New("使用者帳戶已經存在")
	errWeakPW     error = errors.New("密碼強度不夠")
	errDenyAccess error = errors.New("用戶名稱或密碼錯誤")
	errReLogIn    error = errors.New("account has been login")
	// 密碼regex規則
	h     = sha3.New512()
	rule1 = regexp.MustCompile(`[a-z]`)
	rule2 = regexp.MustCompile(`[A-Z]`)
	rule3 = regexp.MustCompile(`.{8,}`)
)

// uData : 認證功能的儲存類別
type uData struct {
	username    string
	passwordSH3 string
	lastChange  time.Time
	expireTime  time.Time
	lastSignIn  time.Time
	loginTime   int64
}

// 從文件"user_auth.data"中進行data binding
func covertToMetaData(data string) (user *uData) {
	// 空對象
	user = &uData{"NULL", "NULL", time.Unix(0, 0), time.Unix(0, 0), time.Unix(0, 0), 0}
	if len(data) < 1 {
		return
	}
	meta := strings.Split(data, ":")
	user.username = meta[0]
	user.passwordSH3 = meta[1]
	label, err := strconv.ParseInt(meta[2], 10, 64)
	dealWith(err)
	user.lastChange = time.Unix(0, label)
	label, err = strconv.ParseInt(meta[3], 10, 64)
	dealWith(err)
	user.expireTime = time.Unix(0, label)
	label, err = strconv.ParseInt(meta[4], 10, 64)
	dealWith(err)
	user.lastSignIn = time.Unix(0, label)
	loginTime, err := strconv.ParseInt(meta[5], 10, 64)
	dealWith(err)
	user.loginTime = loginTime
	return
}

// 將記憶體中的物件轉回data，可寫回認證資料
func (meta *uData) String() string {
	return fmt.Sprintf("%v:%v:%v:%v:%v:%v", meta.username, meta.passwordSH3,
		meta.lastChange.UnixNano(), meta.expireTime.UnixNano(), meta.lastSignIn.UnixNano(), meta.loginTime)
}

// 更新密碼
func (meta *uData) updatePassword(npw []byte) {
	// 更改密碼同時，刷新修改時間、到期時間
	npwSHA3 := hex.EncodeToString(h.Sum(npw))
	meta.passwordSH3 = npwSHA3
	meta.lastChange = time.Now()
	meta.expireTime = meta.lastChange.Add(expireDuration)
}

// 用內部實例更新外部資料
func (meta *uData) updateMeta() {
	// 載入外部資料
	authFile, err := os.OpenFile("user_auth.dat", os.O_RDWR|os.O_CREATE, 0700)
	dealWith(err)
	defer authFile.Close()
	authFile.Seek(0, 0)
	authString, err := ioutil.ReadAll(authFile)
	dealWith(err)
	// 更新資料後全部寫回清空的原認證文件
	authFile.Truncate(0)
	authFile.Seek(0, 0)
	reg := regexp.MustCompile(fmt.Sprintf("%v:(.*):(.*):(.*):(.*):(.*)", meta.username))
	authFile.WriteString(reg.ReplaceAllString(string(authString), meta.String()))
}

// 用外部資料更新內部實例
func (meta *uData) updateFromTable() {
	// 載入整個文件進記憶體
	authFile, err := os.OpenFile("user_auth.dat", os.O_RDWR|os.O_CREATE, 0700)
	dealWith(err)
	defer authFile.Close()
	authFile.Seek(0, 0)
	authString, err := ioutil.ReadAll(authFile)
	dealWith(err)
	// 選擇對應資料列，實例化傳回
	reg := regexp.MustCompile(fmt.Sprintf("%v:(.*):(.*):(.*):(.*):(.*)", meta.username))
	tmp := covertToMetaData(reg.FindString(string(authString)))
	meta.username = tmp.username
	meta.passwordSH3 = tmp.passwordSH3
	meta.lastChange = tmp.lastChange
	meta.expireTime = tmp.expireTime
	meta.lastSignIn = tmp.lastSignIn
	meta.loginTime = tmp.loginTime
}

// 登出動作
func (meta uData) logout() {
	meta.updateFromTable()
	meta.loginTime--
	meta.updateMeta()
}

func main() {
	var (
		uiMode    int  = 0
		denyTimes uint = 0
		user      *uData
	)
	fmt.Println("\033[33mSmall Authentication")
	fmt.Println("Copyright (c) 2021 yuuR-Meow aka JunWeiLiao for Information Security Class")
	fmt.Println("\nThe source code has been uploaded to github.")
	fmt.Println("https://github.com/yuuR-Meow/simple-file-base-muti-user-authentication\033[m")
	for {
		fmt.Println()
		if uiMode == modeGuest /*訪客模式*/ {
			command := prompt.Input("Auth: Guest > ", welcomeCompleter)
			switch command {
			case "login" /*登入*/ :
				//要求輸入帳號密碼
				var uname string
				fmt.Print("\n\t請輸入使用者名稱: ")
				fmt.Scanf("%v\n", &uname)
				fmt.Printf("\t請輸入%v的密碼: ", uname)
				// 隱藏式密碼輸入
				pw, err := term.ReadPassword(int(syscall.Stdin))
				dealWith(err)
				fmt.Println()
				// 登入認證系統
				var lastSignIn string
				user, lastSignIn, err = logIn(uname, pw)
				if err == errDenyAccess {
					// 使用者名稱或密碼錯誤
					fmt.Println("\t", err.Error())
					denyTimes++
					if denyTimes < 3 {
						// 3次內錯誤處理
						fmt.Printf("\t目前已連續失敗%v次，達到3次會強制退出\n", denyTimes)
						continue
					}
					// 錯誤超過容忍
					fmt.Printf("\t目前已連續失敗達到3次，強制退出用戶\n")
					os.Exit(0)
				} else if err == errReLogIn {
					// 重複登入處理
					fmt.Printf("\t[提示]：該帳戶已由其他裝置登入\n")
				}
				fmt.Printf("\t[成功登入]：歡迎%v。\n\t上次登入時間是：%v\n", user.username, lastSignIn)
				denyTimes = 0
				uiMode = modeUser
			case "register" /*註冊*/ :
				//要求輸入帳號密碼
				var uname string
				var pw []byte
				for {
					fmt.Print("\n\t請輸入新的使用者名稱: ")
					fmt.Scanf("%v\n", &uname)
					existed, _ := existedAccount(uname)
					if existed {
						fmt.Printf("\t使用者名稱{%v}已經被註冊\n", uname)
						continue
					}
					break
				}
				for {
					fmt.Printf("\t請輸入%v的密碼: ", uname)
					var err error
					pw, err = term.ReadPassword(int(syscall.Stdin))
					dealWith(err)
					fmt.Println()
					if weakPW(pw) {
						fmt.Printf("\t%v\n\t\t%v\n\t\t%v\n\t\t%v\n",
							"該密碼強度不足，須滿足",
							"(1).長度要達到8",
							"(2).密碼須包含英文大寫",
							"(3).密碼須包含英文小寫")
						continue
					}
					break
				}
				createAccount(uname, pw)
				fmt.Printf("\t使用者{%v}，註冊程序已完成，將跳轉回首頁\n", uname)
			case "bye" /*結束*/ :
				//離開程式
				fmt.Println("Bye!")
				os.Exit(0)
			default /*未知指令*/ :
				fmt.Printf("%v : 系統無法辨識的指令，請使用tab重新確認\n", command)
			}
		} else if uiMode == modeUser /*使用者模式*/ {
			// 確認使用者帳戶期限
			user.updateFromTable()
			if user.expireTime.Before(time.Now()) {
				// 如果到期，強制修改密碼
				fmt.Printf("\t\033[91m[Caution]現在時間：{%v}\n", time.Now())
				fmt.Printf("\t[Caution]到期時間：{%v}\n", user.expireTime)
				fmt.Println("\t[Caution]密碼已到期，請更改\033[m")
				for {
					// 要求新的密碼
					fmt.Print("\n\t請輸入新的密碼: ")
					var err error
					npw, err := term.ReadPassword(int(syscall.Stdin))
					dealWith(err)
					fmt.Println()
					if weakPW(npw) {
						fmt.Printf("\t%v\n\t\t%v\n\t\t%v\n\t\t%v\n",
							"該密碼強度不足，須滿足",
							"(1).長度要達到8",
							"(2).密碼須包含英文大寫",
							"(3).密碼須包含英文小寫")
						continue
					}
					// 更新密碼
					user.updatePassword(npw)
					user.updateMeta()
					fmt.Printf("\t\033[93m密碼已更新完畢，下個到期日為：{%v}\033[m\n", user.expireTime)
					fmt.Println()
					break
				}
				// 強制登出
				user.logout()
				uiMode = modeGuest
				continue
			}
			tips := fmt.Sprintf("Auth: [user]%v > ", user.username)
			command := prompt.Input(tips, userCompleter)
			switch command {
			case "logout" /*登出*/ :
				user.logout()
				uiMode = modeGuest
				fmt.Printf("\t[成功登出]：期待使用者{%v}下次登入。\n", user.username)
				continue
			case "inquire" /*查詢*/ :
				// 顯示認證資料可查詢項目
				user.updateFromTable()
				fmt.Printf("\n\t使用者名稱：{%v}\n\t通行證：{無法查看}\n", user.username)
				fmt.Printf("\t上次密碼更改：{%v}\n\t密碼到期日期：{%v}\n", user.lastChange, user.expireTime)
				fmt.Printf("\t最近登入時間：{%v}\n\t登入裝置數量：{%v}\n", user.lastSignIn, user.loginTime)
			case "bye" /*結束*/ :
				// 和登出動作一樣
				user.logout()
				fmt.Println("Bye!")
				os.Exit(0)
			default /*未知指令*/ :
				fmt.Printf("%v : 系統無法辨識的指令，請使用tab重新確認\n", command)
			}
		}
	}
}

// 創建新使用者
func createAccount(uname string, pw []byte) error {
	//準備資料，pwSHA=>雜湊後密碼、accExisted=>檢查使用者是否已經存在
	pwSHA3 := hex.EncodeToString(h.Sum(pw))
	accExisted, _ := existedAccount(uname)
	if accExisted {
		return errAccExisted
	}
	// 密碼不符合規則
	if weakPW(pw) {
		return errWeakPW
	}
	// 將新使用者資訊寫入外部登入文件
	authFile, err := os.OpenFile("user_auth.dat", os.O_RDWR|os.O_CREATE, 0700)
	dealWith(err)
	defer authFile.Close()
	authFile.Seek(0, 2)
	fmt.Fprintf(authFile, "%v:%v:%v:%v:%v:0\n", uname, pwSHA3, time.Now().UnixNano(),
		time.Now().Add(expireDuration).UnixNano(), time.Now().UnixNano())
	return nil
}

// 登入認證系統
func logIn(uname string, pw []byte) (*uData, string, error) {
	// 認證，並傳回使用者資料實例和上次登入時間
	access, acc := verify(uname, pw)
	if !access {
		return acc, "", errDenyAccess
	}
	// 更新使用者的最近登入時間、登入裝置數量
	lastSignIn := acc.lastSignIn.String()
	acc.lastSignIn = time.Now()
	acc.loginTime++
	acc.updateMeta()
	if acc.loginTime > 1 {
		// 重複登入警告
		return acc, lastSignIn, errReLogIn
	}
	return acc, lastSignIn, nil
}

// 主認證功能
func verify(uname string, pw []byte) (bool, *uData) {
	// 準備資料，進行比對
	pwSHA3 := hex.EncodeToString(h.Sum(pw))
	existed, account := existedAccount(uname)
	if !existed || account.passwordSH3 != pwSHA3 {
		return false, account
	}
	return true, account
}

// 從外部認證資料，確認使用者是否已經建立
func existedAccount(uname string) (bool, *uData) {
	// 先載入新的外部資料
	meta := covertToMetaData("")
	meta.username = uname
	meta.updateFromTable()
	if meta.passwordSH3 == "NULL" {
		return false, meta
	}
	return true, meta
}

// 密碼強度檢測。true=>弱、false=>強
func weakPW(pw []byte) bool {
	//regex的backahead在golang regexp庫不支援（基於google re2）
	//(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}
	return !(rule1.Match(pw) && rule2.Match(pw) && rule3.Match(pw))
}

// 錯誤處理
func dealWith(err error) {
	if err != nil {
		panic(err)
	}
}

// 訪客提示
func welcomeCompleter(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "login", Description: "登入此系統程式"},
		{Text: "register", Description: "註冊成為新的使用者"},
		{Text: "bye", Description: "離開登入系統程式"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

// 使用者提示
func userCompleter(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "logout", Description: "登出，回到首頁"},
		{Text: "inquire", Description: "查詢使用者的登入資訊"},
		{Text: "bye", Description: "離開登入系統程式"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

// Copyright (c) 2021 yuuR-Meow aka JunWeiLiao for Information Security Class
