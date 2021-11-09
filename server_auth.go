/*
 * @Author: wang
 * @Date: 2021-11-09 20:28:57
 * @LastEditTime: 2021-11-09 22:19:30
 * @LastEditors: Please set LastEditors
 * @Description: 服务端相关加密、校验函数
 * @FilePath: /cross_authenticate/server_auth.go
 */
package crossauthenticate

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// 生成token(即T)的方法.返回的加密字符串长度固定32个字符,有效字符只含有a-f（小写），0-9
//  params
//   {string} text 需要传入一个字符串，将针对其内容进行加密
//  return
//   {string} 返回加密的字符串
func GenerateT(text string) string {
	nano := time.Now().UnixNano()
	seed := text + strconv.FormatInt(nano, 16)
	ciphertext := md5.Sum([]byte(seed))
	t := hex.EncodeToString(ciphertext[:])
	return strings.ToLower(t)
}

// 进行验证
//  params
//    {string} ts: 认证体系应表示为用户在服务器端寄存的原始token，即TS；如果非认证体系，则应该表示为服务器统一存储的T。长度必须为32位
//    {string} E: 客户端通过request.head 发回的认证信息.长度必须为36位
//  return
//    {bool}: 如果error返回nil,bool返回true，则指示身份验证成功；否则验证失败
//    {error}: 正常情况应该返回nil，如果不为nil则表示过程中有错误发生，同时布尔值为false(只是为了返回值，并无参考价值)
func Authenticate(t string, E string) (bool, error) {
	if len(t) != 32 {
		return false, errors.New("len(t)!=32")
	}
	if len(E) != 36 {
		return false, errors.New("len(E)!=36")
	}
	pos := 8
	step := 9
	var keybuild strings.Builder
	for i := 0; i < 4; i++ {
		keybuild.WriteString(string(E[pos]))
		//println(string(E[pos]))
		pos += step
	}
	key := keybuild.String()
	test_E, err := generateE(t, key)
	if err != nil {
		return false, err
	}
	if E != test_E {
		return false, nil
	}
	return true, nil
}

// 还原E的过程。服务器端不存在生成E的过程，所以该函数应为私有函数，目的不是为了生成E，而是通过生成E进行校验:
//  params
//    {string} t: 原始token，认证模式应为TS，非认证模式应为T
//    {string} key: 客户端通过E传回的key（从E中抽离出来的4位key）
//  return
//    {string}: 最终形成的E
//    {error}: 如果转换过程中产生错误则不为nil
func generateE(t string, key string) (string, error) {
	if len(t) != 32 {
		return "", errors.New("len(t)!=32")
	}
	if len(key) != 4 {
		return "", errors.New("len(E)!=36")
	}
	seed := strings.ToLower(key + t)
	m := md5.Sum([]byte(seed))
	token := strings.ToLower(hex.EncodeToString(m[:]))
	var sb strings.Builder
	sb.WriteString(token[0:8])
	sb.WriteString(string(key[0]))
	sb.WriteString(token[8:16])
	sb.WriteString(string(key[1]))
	sb.WriteString(token[16:24])
	sb.WriteString(string(key[2]))
	sb.WriteString(token[24:32])
	sb.WriteString(string(key[3]))
	return sb.String(), nil
}
