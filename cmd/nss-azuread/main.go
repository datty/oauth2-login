package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/datty/pam-azuread/internal/conf"
	"github.com/datty/pam-azuread/internal/passwd"

	"github.com/shirou/gopsutil/v3/process"

	nss "github.com/protosam/go-libnss"
	nssStructs "github.com/protosam/go-libnss/structs"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// app name
const app = "nss-azuread"

// Placeholder main() stub is neccessary for compile.
func main() {}

func init() {
	// We set our implementation to "LibNssOauth", so that go-libnss will use the methods we create
	nss.SetImpl(LibNssOauth{})
}

// LibNssExternal creates a struct that implements LIBNSS stub methods.
type LibNssOauth struct{ nss.LIBNSS }

var config *conf.Config

func (self LibNssOauth) oauth_init() (result confidential.AuthResult, err error) {

	//Enable Debug Logging - REMOVE ME! ----------------
	f, err := os.OpenFile("/var/log/"+app+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	//Enable Debug Logging - REMOVE ME! ----------------

	//Load config vars
	if config == nil {
		if config, err = conf.ReadConfig(); err != nil {
			log.Println("unable to read configfile:", err)
			return result, err
		}
	}

	//Enable oauth cred cache
	cacheAccessor := &TokenCache{"/var/tmp/" + app + "_cache.json"}

	//Attempt oauth
	cred, err := confidential.NewCredFromSecret(config.ClientSecret)
	if err != nil {
		log.Fatal(err)
	}
	app, err := confidential.New(config.ClientID, cred, confidential.WithAuthority("https://login.microsoftonline.com/"+config.TenantID), confidential.WithAccessor(cacheAccessor))
	if err != nil {
		log.Fatal(err)
	}
	result, err = app.AcquireTokenSilent(context.Background(), config.NssScopes)
	if err != nil {
		result, err = app.AcquireTokenByCredential(context.Background(), config.NssScopes)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Access Token Is " + result.AccessToken)
		return result, err
	}
	log.Println("Silently acquired token " + result.AccessToken)
	return result, err

}

// PasswdAll will populate all entries for libnss
func (self LibNssOauth) PasswdAll() (nss.Status, []nssStructs.Passwd) {
	return nss.StatusSuccess, []nssStructs.Passwd{}
}

// PasswdByName returns a single entry by name.
func (self LibNssOauth) PasswdByName(name string) (nss.Status, nssStructs.Passwd) {

	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		log.Println("username", name, "did not match 'name-regex':", err)
		return nss.StatusNotfound, nssStructs.Passwd{}
	}
	log.Println("Test output %s", result)

	if config.CreateUser {
		// create user if none exists
		if _, err := passwd.Lookup(name); err != nil {
			useradd, err := exec.LookPath("/usr/sbin/useradd")

			if err != nil {
				log.Println("useradd command was not found:", err)
				return nss.StatusNotfound, nssStructs.Passwd{}
			}

			args := []string{"-m", "-s", "/bin/bash", "-c", app, name}
			commandline := useradd + " " + strings.Join(args, " ")

			// 'useradd' will call getpwnam() first. We must check if we get here
			// from this call to avoid a recursion.
			processes, err := process.Processes()

			if err != nil {
				log.Println("unable to read process list:", err)
				return nss.StatusNotfound, nssStructs.Passwd{}
			}

			for _, p := range processes {
				pcmd, err := p.Cmdline()
				if err != nil {
					log.Println("unable to read process list:", err)
					return nss.StatusNotfound, nssStructs.Passwd{}
				}

				if pcmd == commandline {
					// 'useradd' already running
					return nss.StatusNotfound, nssStructs.Passwd{}
				}
			}

			cmd := exec.Command(useradd, args...)
			out, err := cmd.CombinedOutput()

			if err != nil {
				log.Println("unable to create user output:", string(out), err)
				return nss.StatusNotfound, nssStructs.Passwd{}
			}
		}
	}

	// user should have been created by now
	osuser, err := passwd.Lookup(name)
	if err != nil {
		log.Println("user", name, "not found in passwd:", err)
		return nss.StatusNotfound, nssStructs.Passwd{}
	}

	passwd := nssStructs.Passwd{
		Username: osuser.Name,
		Password: "*",
		UID:      osuser.UID,
		GID:      osuser.GID,
		Shell:    osuser.Shell,
		Dir:      osuser.HomeDir,
		Gecos:    osuser.Gecos,
	}

	return nss.StatusSuccess, passwd
}

// PasswdByUid returns a single entry by uid, not managed here
func (self LibNssOauth) PasswdByUid(uid uint) (nss.Status, nssStructs.Passwd) {
	return nss.StatusNotfound, nssStructs.Passwd{}
}

// GroupAll returns all groups, not managed here
func (self LibNssOauth) GroupAll() (nss.Status, []nssStructs.Group) {
	// fmt.Printf("GroupAll\n")
	return nss.StatusSuccess, []nssStructs.Group{}
}

// GroupByName returns a group, not managed here
func (self LibNssOauth) GroupByName(name string) (nss.Status, nssStructs.Group) {
	// fmt.Printf("GroupByName %s\n", name)
	return nss.StatusNotfound, nssStructs.Group{}
}

// GroupBuGid retusn group by id, not managed here
func (self LibNssOauth) GroupByGid(gid uint) (nss.Status, nssStructs.Group) {
	// fmt.Printf("GroupByGid %d\n", gid)
	return nss.StatusNotfound, nssStructs.Group{}
}

// ShadowAll return all shadow entries, not managed as no password are allowed here
func (self LibNssOauth) ShadowAll() (nss.Status, []nssStructs.Shadow) {
	// fmt.Printf("ShadowAll\n")
	return nss.StatusSuccess, []nssStructs.Shadow{}
}

// ShadowByName return shadow entry, not managed as no password are allowed here
func (self LibNssOauth) ShadowByName(name string) (nss.Status, nssStructs.Shadow) {
	// fmt.Printf("ShadowByName %s\n", name)
	return nss.StatusNotfound, nssStructs.Shadow{}
}
