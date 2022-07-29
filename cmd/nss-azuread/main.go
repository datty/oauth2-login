package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/datty/pam-azuread/internal/conf"

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

//Request against Microsoft Graph API using token, return JSON
func (self LibNssOauth) msgraph_req(t string, req string) (output map[string]interface{}, err error) {

	requestURL := fmt.Sprintf("https://graph.microsoft.com:443/%s", req)
	token := fmt.Sprintf("Bearer %s", t)

	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	request.Header.Set("Authorization", token)
	if err != nil {
		return output, err
	}
	res, err := http.DefaultClient.Do(request)
	if err != nil {
		return output, err
	}
	//Check if valid response
	if res.StatusCode != 200 {
		return output, fmt.Errorf("%v", res.StatusCode)
	}
	//Close output I guess???
	if res.Body != nil {
		defer res.Body.Close()
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	jsonErr := json.Unmarshal([]byte(body), &output)
	if jsonErr != nil {
		log.Fatal(err)
	}
	return output, nil
}

// PasswdAll will populate all entries for libnss
func (self LibNssOauth) PasswdAll() (nss.Status, []nssStructs.Passwd) {

	//Enable Debug Logging - REMOVE ME! ----------------
	f, err := os.OpenFile("/var/log/"+app+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	//Enable Debug Logging - REMOVE ME! ----------------

	//Get OAuth token
	result, err := self.oauth_init()
	log.Println("Test output %s", result)
	if err != nil {
		log.Println("Oauth Failed:", err)
	}

	return nss.StatusSuccess, []nssStructs.Passwd{}
}

// PasswdByName returns a single entry by name.
func (self LibNssOauth) PasswdByName(name string) (nss.Status, nssStructs.Passwd) {

	//Enable Debug Logging - REMOVE ME! ----------------
	f, err := os.OpenFile("/var/log/"+app+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	//Enable Debug Logging - REMOVE ME! ----------------

	//Get OAuth token
	result, err := self.oauth_init()
	log.Println("Test output %s", result)
	if err != nil {
		log.Println("Oauth Failed:", err)
	}

	// Azure User Lookup - Disable for now.
	//getUserQuery := fmt.Sprintf("v1.0/users/%s?$select=id,displayName,customSecurityAttributes", fmt.Sprintf(config.Domain, name))
	//jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)

	if err != nil {
		log.Println("unable to create user output:", err)
		return nss.StatusNotfound, nssStructs.Passwd{}
	}
	//Disable function for now.
	return nss.StatusNotfound, nssStructs.Passwd{}
}

// PasswdByUid returns a single entry by uid, not managed here
func (self LibNssOauth) PasswdByUid(uid uint) (nss.Status, nssStructs.Passwd) {
	return nss.StatusNotfound, nssStructs.Passwd{}
}

// GroupAll returns all groups
func (self LibNssOauth) GroupAll() (nss.Status, []nssStructs.Group) {
	//Get OAuth token
	result, err := self.oauth_init()
	log.Println("Test output %s", result)
	if err != nil {
		log.Println("Oauth Failed:", err)
	}

	// Azure User Lookup URL
	//graphUrl := fmt.Sprintf("v1.0/groups")
	//Pull all groups from Azure
	//json, err := self.msgraph_req(result.AccessToken, graphUrl)
	if err != nil {
		log.Println("Graph API call failed:", err)
	}
	//for _, value := range json["value"].([]interface{}) {
	//Map value var to correct type
	//	xx := value.(map[string]interface{})
	//}
	//Disable for now. Not a hard requirement.
	//return nss.StatusSuccess, []nssStructs.Group{}
	return nss.StatusNotfound, []nssStructs.Group{}
}

// GroupByName returns a group, not managed here
func (self LibNssOauth) GroupByName(name string) (nss.Status, nssStructs.Group) {

	//Get OAuth token
	result, err := self.oauth_init()
	log.Println("Test output %s", result)
	if err != nil {
		log.Println("Oauth Failed:", err)
	}

	//If User doesn't exist and we have creategroup enabled...
	if err != nil && config.CreateGroup {

		// Azure User Lookup URL
		graphUrl := fmt.Sprintf("v1.0/groups")
		//Pull all groups from Azure
		json, err := self.msgraph_req(result.AccessToken, graphUrl)
		if err != nil {
			log.Println("Graph API call failed:", err)
		}

		//Set default fail for group var
		groupExists := false

		for _, value := range json["value"].([]interface{}) {
			//Map value var to correct type
			xx := value.(map[string]interface{})
			//Check for group name match
			if xx["displayName"] == name {
				groupExists = true
			}
		}
		// create group if none exists
		if groupExists == true {
			groupadd, err := exec.LookPath("/usr/sbin/groupadd")

			if err != nil {
				log.Println("groupadd command was not found:", err)
				return nss.StatusNotfound, nssStructs.Group{}
			}

			//args := []string{"-g", gid, name}
			args := []string{name}
			commandline := groupadd + " " + strings.Join(args, " ")

			// 'useradd' will call getpwnam() first. We must check if we get here
			// from this call to avoid a recursion.
			processes, err := process.Processes()

			if err != nil {
				log.Println("unable to read process list:", err)
				return nss.StatusNotfound, nssStructs.Group{}
			}

			for _, p := range processes {
				pcmd, err := p.Cmdline()
				if err != nil {
					log.Println("unable to read process list:", err)
					return nss.StatusNotfound, nssStructs.Group{}
				}

				if pcmd == commandline {
					// 'groupadd' already running
					return nss.StatusNotfound, nssStructs.Group{}
				}
			}

			cmd := exec.Command(groupadd, args...)
			out, err := cmd.CombinedOutput()

			if err != nil {
				log.Println("unable to create group output:", string(out), err)
				return nss.StatusNotfound, nssStructs.Group{}
			}
		}
	}

	//disable for now.
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
