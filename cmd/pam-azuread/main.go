// Copyright © 2017 Shinichi MOTOKI
// Copyright © 2022 Oliver Smith
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

//#include <security/pam_appl.h>
import "C"
import (
	"context"
	"runtime"
	"strings"

	"fmt"
	"log/syslog"

	"github.com/datty/pam-azuread/internal/conf"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"gopkg.in/square/go-jose.v2/jwt"
)

// app name
const app = "pam_azuread"

func pamLog(format string, args ...interface{}) {
	l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, app)
	if err != nil {
		return
	}
	l.Warning(fmt.Sprintf(format, args...))
}

func pamAuthenticate(pamh *C.pam_handle_t, uid int, username string, argv []string) int {
	runtime.GOMAXPROCS(1)

	config, err := conf.ReadConfig()
	if err != nil {
		pamLog("Error reading config: %v", err)
		return PAM_OPEN_ERR
	}

	password := strings.TrimSpace(requestPass(pamh, C.PAM_PROMPT_ECHO_OFF, "AzureAD-Password: "))

	//Open AzureAD
	app, err := public.New(config.ClientID, public.WithAuthority("https://login.microsoftonline.com/"+config.TenantID))
	if err != nil {
		pamLog("Error opening AzureAD connection: %v", err)
		return PAM_OPEN_ERR
	}

	//Auth with Username/Password
	pamLog("Attempting token auth for user: %s", fmt.Sprintf(config.Domain, username))
	result, err := app.AcquireTokenByUsernamePassword(
		context.Background(),
		config.PamScopes,
		fmt.Sprintf(config.Domain, username),
		password,
	)
	if err != nil {
		pamLog("AzureAD authentication failed for user: %s. Error: %v", fmt.Sprintf(config.Domain, username), err)
		return PAM_AUTH_ERR
	}

	// check token is valid
	if validateToken(result.AccessToken) {
		pamLog("AzureAD authentication succeeded for user: %s", fmt.Sprintf(config.Domain, username))
		return PAM_SUCCESS
	} else {
		pamLog("AzureAD token invalid, authentication failed for user: %s", fmt.Sprintf(config.Domain, username))
		return PAM_AUTH_ERR
	}

}

// main is for testing purposes only, the PAM module has to be built with:
// go build -buildmode=c-shared
func main() {

}

// validateToken - Check if JWT token can be parsed as a valid token
func validateToken(t string) bool {
	_, err := jwt.ParseSigned(t)
	if err != nil {
		return false
	}
	return true
}
