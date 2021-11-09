/*
 * @Author: your name
 * @Date: 2021-11-09 22:05:59
 * @LastEditTime: 2021-11-09 22:26:16
 * @LastEditors: Please set LastEditors
 * @Description: 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 * @FilePath: /cross_authenticate/cross_authenticate/server/server_auth_test.go
 */

package crossauthenticate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GenerateT(t *testing.T) {
	a := assert.New(t)
	token := GenerateT("u001")
	t.Log("generate token: ", token)
	a.Equal(32, len(token))
}

func Test_AuthOK(t *testing.T) {
	a := assert.New(t)
	t1 := GenerateT("u001")
	E, err := generateE(t1, "0f01")
	a.Nil(err)
	t.Log("E: ", E)
	ok, err := Authenticate(t1, E)
	a.Nil(err)
	a.Equal(true, ok)
	a.Equal(36, len(E))
}
