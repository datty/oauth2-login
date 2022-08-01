package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/datty/pam-azuread/internal/conf"

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
	request.Header.Set("ConsistencyLevel", "eventual")
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

//Patch request against Microsoft Graph API using token, return status
func (self LibNssOauth) msgraph_update(t string, req string, val []byte) (status bool, err error) {
	requestURL := fmt.Sprintf("https://graph.microsoft.com:443/%s", req)
	token := fmt.Sprintf("Bearer %s", t)

	request, err := http.NewRequest(http.MethodPatch, requestURL, bytes.NewBuffer(val))
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("Authorization", token)
	if err != nil {
		return false, err
	}
	res, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, err
	}
	//Check if valid response
	if res.StatusCode != 204 {
		return false, fmt.Errorf("%v", res.StatusCode)
	} else {
		return true, nil
	}
}

func (self LibNssOauth) GetUnusedUID(t string) (output uint, err error) {

	//Build all users query. Filters users without licences and only returns required fields.
	getUIDQuery := "/users?$filter=assignedLicenses/$count+ne+0&$count=true&$select="
	if config.UseSecAttributes {
		//Uses 'beta' endpoint as customSecurityAttributes are only available there.
		getUIDQuery = "beta" + getUIDQuery + "customSecurityAttributes"
		log.Println("Query: %s", getUIDQuery) //DEBUG
	} else {
		getUIDQuery = "v1.0" + getUIDQuery + config.UserUIDAttribute
		log.Println("Query: %s", getUIDQuery) //DEBUG
	}
	jsonOutput, err := self.msgraph_req(t, getUIDQuery)
	if err != nil {
		log.Println("MSGraph request failed:", err)
		return 0, err
	}

	//Create empty uidlist
	uidList := []int{}

	//Collect existing uids
	for _, userResult := range jsonOutput["value"].([]interface{}) {
		//Map value var to correct type to allow for access
		xx := userResult.(map[string]interface{})

		//Get UIDs
		if config.UseSecAttributes {
			//Set variables ready...not sure if there's a better way to handle this.
			var userSecAttributes map[string]interface{}
			var attributeSet map[string]interface{}
			//Check whether CSA-SA exists
			if xx["customSecurityAttributes"] != nil {
				userSecAttributes = xx["customSecurityAttributes"].(map[string]interface{})
				if userSecAttributes != nil {
					attributeSet = userSecAttributes[config.AttributeSet].(map[string]interface{})
					if attributeSet[config.UserUIDAttribute] != nil {
						//UID exists
						uidList = append(uidList, int(attributeSet[config.UserUIDAttribute].(float64)))
					}
				}
			}
		} else {
			if xx[config.UserUIDAttribute] != nil {
				uidList = append(uidList, int(xx[config.UserUIDAttribute].(float64)))
			}
		}
	}
	//Sort UIDs backwards
	sort.Sort(sort.Reverse(sort.IntSlice(uidList)))
	newUID := uint(uidList[0] + rand.Intn(20))

	return newUID, nil
}

//Post request against Microsoft Graph API using token, return status
func (self LibNssOauth) AutoSetUID(t string, userid string) (uid uint, err error) {

	//Get Next Available UID
	uid, err = self.GetUnusedUID(t)
	if err != nil {
		return 0, err
	}

	//Build query and body to set UID
	var json string
	getUIDQuery := "/users/" + userid
	if config.UseSecAttributes {
		//Uses 'beta' endpoint as customSecurityAttributes are only available there.
		getUIDQuery = "beta" + getUIDQuery
		log.Println("Query: %s", getUIDQuery) //DEBUG

		//Set JSON
		json = fmt.Sprintf(`{
			"customSecurityAttributes": {
				"%s": {
					"@odata.type": "#microsoft.graph.customSecurityAttributeValue",
					"%s@odata.type":"#Int32",
					"%s": %d
				}
			}
		}`, config.AttributeSet, config.UserUIDAttribute, config.UserUIDAttribute, uid)
		log.Println("JSON: %s", json)
	} else {
		getUIDQuery = "v1.0" + getUIDQuery
		log.Println("Query: %s", getUIDQuery) //DEBUG

		//Set JSON
		json = fmt.Sprintf(`{
			"%s": %d
		}`, config.UserUIDAttribute, uid)
	}

	_, err = self.msgraph_update(t, getUIDQuery, []byte(json))

	if err != nil {
		log.Println("MSGraph request failed:", err)
		return 0, err
	}
	return uid, err

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
		return nss.StatusUnavail, []nssStructs.Passwd{}
	}

	//Build all users query. Filters users without licences and only returns required fields.
	getUserQuery := "/users?$filter=assignedLicenses/$count+ne+0&$count=true&$select=id,userPrincipalName"
	if config.UseSecAttributes {
		//Uses 'beta' endpoint as customSecurityAttributes are only available there.
		getUserQuery = "beta" + getUserQuery + ",customSecurityAttributes"
		log.Println("Query: %s", getUserQuery) //DEBUG
	} else {
		getUserQuery = "v1.0" + getUserQuery + "," + config.UserUIDAttribute + "," + config.UserGIDAttribute
		log.Println("Query: %s", getUserQuery) //DEBUG
	}
	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		log.Println("MSGraph request failed:", err)
		return nss.StatusUnavail, []nssStructs.Passwd{}
	}

	//Open Slice/Struct for result
	passwdResult := []nssStructs.Passwd{}

	for _, userResult := range jsonOutput["value"].([]interface{}) {
		//Create temporary struct for user info
		tempUser := nssStructs.Passwd{}
		//Create error capture val
		userUIDErr := true

		//Map value var to correct type to allow for access
		xx := userResult.(map[string]interface{})

		//Set default GID
		tempUser.GID = config.UserDefaultGID

		//Get UID/GID
		if config.UseSecAttributes {
			//Set variables ready...not sure if there's a better way to handle this.
			var userSecAttributes map[string]interface{}
			var attributeSet map[string]interface{}
			//Check whether CSA exists
			if xx["customSecurityAttributes"] != nil {
				userSecAttributes = xx["customSecurityAttributes"].(map[string]interface{})
				if userSecAttributes != nil {
					attributeSet = userSecAttributes[config.AttributeSet].(map[string]interface{})
					//Get UID/GID from CSA-AS
					if attributeSet[config.UserUIDAttribute] != nil {
						//UID exists
						tempUser.UID = uint(attributeSet[config.UserUIDAttribute].(float64))
						userUIDErr = false
					}
					if attributeSet[config.UserGIDAttribute] != nil {
						//GID exists
						tempUser.GID = uint(attributeSet[config.UserGIDAttribute].(float64))
					}
				} else {
					log.Println("No CSA-AS") //DEBUG
				}
			}
		} else {
			if xx[config.UserUIDAttribute] != nil {
				tempUser.UID = xx[config.UserUIDAttribute].(uint)
				userUIDErr = false
			}
			if xx[config.UserGIDAttribute] != nil {
				tempUser.GID = xx[config.UserGIDAttribute].(uint)
			}
		}
		//Strip domain from UPN
		user := strings.Split(xx["userPrincipalName"].(string), "@")[0]

		//Set user info
		tempUser.Username = user
		tempUser.Password = "x"
		tempUser.Gecos = app
		tempUser.Dir = fmt.Sprintf("/home/%s", user)
		tempUser.Shell = "/bin/bash"

		//Add this user to result if no errors flagged
		if userUIDErr == true {
			//Do the magic and set UID
			tempUser.UID, err = self.AutoSetUID(result.AccessToken, xx["id"].(string))
			//AzureAD eventual consistency...Pause to prevent UID clash
			time.Sleep(5 * time.Second)
			log.Println("UserID: %s", xx["id"].(string))
			log.Println("User: %s", xx["userPrincipalName"].(string))
			log.Println("New UID: %s", tempUser.UID)
		}
		passwdResult = append(passwdResult, tempUser)
	}

	return nss.StatusSuccess, passwdResult
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
		return nss.StatusUnavail, nssStructs.Passwd{}
	}

	//Build all users query, only returns required fields
	username := fmt.Sprintf(config.Domain, name)

	getUserQuery := "/users/" + username + "?$count=true&$select=id,userPrincipalName"
	if config.UseSecAttributes {
		//Uses 'beta' endpoint as customSecurityAttributes are only available there.
		getUserQuery = "beta" + getUserQuery + ",customSecurityAttributes"
		log.Println("Query: %s", getUserQuery) //DEBUG
	} else {
		getUserQuery = "v1.0" + getUserQuery + "," + config.UserUIDAttribute + "," + config.UserGIDAttribute
		log.Println("Query: %s", getUserQuery) //DEBUG
	}
	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		log.Println("MSGraph request failed:", err)
		return nss.StatusNotfound, nssStructs.Passwd{}
	}

	//Open Struct for result
	passwdResult := nssStructs.Passwd{}
	//Create error capture val
	userUIDErr := true

	//Set default GID
	passwdResult.GID = config.UserDefaultGID

	//Get UID/GID
	if config.UseSecAttributes {
		//Set variables ready...not sure if there's a better way to handle this.
		var userSecAttributes map[string]interface{}
		var attributeSet map[string]interface{}
		//Check whether CSA exists
		if jsonOutput["customSecurityAttributes"] != nil {
			userSecAttributes = jsonOutput["customSecurityAttributes"].(map[string]interface{})
			if userSecAttributes != nil {
				attributeSet = userSecAttributes[config.AttributeSet].(map[string]interface{})
				//Get UID/GID from CSA-AS
				if attributeSet[config.UserUIDAttribute] != nil {
					//UID exists
					passwdResult.UID = uint(attributeSet[config.UserUIDAttribute].(float64))
					userUIDErr = false
				}
				if attributeSet[config.UserGIDAttribute] != nil {
					//GID exists
					passwdResult.GID = uint(attributeSet[config.UserGIDAttribute].(float64))
				}
			} else {
				log.Println("No CSA-AS") //DEBUG
			}
		}
	} else {
		if jsonOutput[config.UserUIDAttribute] != nil {
			passwdResult.UID = jsonOutput[config.UserUIDAttribute].(uint)
			userUIDErr = false
		}
		if jsonOutput[config.UserGIDAttribute] != nil {
			passwdResult.GID = jsonOutput[config.UserGIDAttribute].(uint)
		}
	}
	//Strip domain from UPN
	user := strings.Split(jsonOutput["userPrincipalName"].(string), "@")[0]

	//Set user info
	passwdResult.Username = user
	passwdResult.Password = "x"
	passwdResult.Gecos = app
	passwdResult.Dir = fmt.Sprintf("/home/%s", user)
	passwdResult.Shell = "/bin/bash"

	//Add this user to result if no errors flagged
	if userUIDErr == true {
		//Do the magic and set UID
		passwdResult.UID, err = self.AutoSetUID(result.AccessToken, jsonOutput["id"].(string))
		log.Println("UserID: %s", jsonOutput["id"].(string))              //DEBUG
		log.Println("User: %s", jsonOutput["userPrincipalName"].(string)) //DEBUG
		log.Println("New UID: %s", passwdResult.UID)                      //DEBUG
	}

	return nss.StatusSuccess, passwdResult
}

// PasswdByUid returns a single entry by uid, not managed here
func (self LibNssOauth) PasswdByUid(uid uint) (nss.Status, nssStructs.Passwd) {
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
		return nss.StatusUnavail, nssStructs.Passwd{}
	}

	getUserQuery := "/users/?$count=true&$select=id,userPrincipalName"
	if config.UseSecAttributes {
		//Uses 'beta' endpoint as customSecurityAttributes are only available there.
		getUserQuery = "beta" + getUserQuery + ",customSecurityAttributes&$filter=customSecurityAttributes/" + config.AttributeSet + "/" + config.UserUIDAttribute + "+eq+" + fmt.Sprintf("%d", uid)
		log.Println("Query: %s", getUserQuery) //DEBUG
	} else {
		getUserQuery = "v1.0" + getUserQuery + "," + config.UserUIDAttribute + "," + config.UserGIDAttribute + "&$filter=" + config.UserUIDAttribute + "+eq+" + fmt.Sprintf("%d", uid)
		log.Println("Query: %s", getUserQuery) //DEBUG
	}
	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		log.Println("MSGraph request failed:", err)
		return nss.StatusNotfound, nssStructs.Passwd{}
	}

	//Parse jsonOutput to something usable...
	xx := jsonOutput["value"].([]interface{})
	xy := xx[0].(map[string]interface{})

	//Open Struct for result
	passwdResult := nssStructs.Passwd{}

	//Set default GID
	passwdResult.GID = config.UserDefaultGID

	//Get UID/GID
	if config.UseSecAttributes {
		//Set variables ready...not sure if there's a better way to handle this.
		userSecAttributes := xy["customSecurityAttributes"].(map[string]interface{})
		attributeSet := userSecAttributes[config.AttributeSet].(map[string]interface{})
		passwdResult.UID = uint(attributeSet[config.UserUIDAttribute].(float64))
		if attributeSet[config.UserGIDAttribute] != nil {
			//GID exists
			passwdResult.GID = uint(attributeSet[config.UserGIDAttribute].(float64))
		}
	} else {
		passwdResult.UID = xy[config.UserUIDAttribute].(uint)
		if xy[config.UserGIDAttribute] != nil {
			passwdResult.GID = xy[config.UserGIDAttribute].(uint)
		}
	}
	//Strip domain from UPN
	user := strings.Split(xy["userPrincipalName"].(string), "@")[0]

	//Set user info
	passwdResult.Username = user
	passwdResult.Password = "x"
	passwdResult.Gecos = app
	passwdResult.Dir = fmt.Sprintf("/home/%s", user)
	passwdResult.Shell = "/bin/bash"

	return nss.StatusSuccess, passwdResult
}

// GroupAll returns all groups
func (self LibNssOauth) GroupAll() (nss.Status, []nssStructs.Group) {
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
		return nss.StatusUnavail, []nssStructs.Group{}
	}

	//Build all groups query. Filters users without licences and only returns required fields.
	getGroupQuery := "v1.0/groups?$count=true&$filter=securityEnabled+eq+true&$expand=members($select=id,userPrincipalName)&$select=id,displayName"
	log.Println("Query: %s", getGroupQuery) //DEBUG
	jsonOutput, err := self.msgraph_req(result.AccessToken, getGroupQuery)
	if err != nil {
		log.Println("MSGraph request failed:", err)
		return nss.StatusUnavail, []nssStructs.Group{}
	}

	//Open Slice/Struct for result
	groupResult := []nssStructs.Group{}

	for _, result := range jsonOutput["value"].([]interface{}) {
		//Create temporary struct for group info
		tempGroup := nssStructs.Group{}

		//Map value var to correct type to allow for access
		xx := result.(map[string]interface{})

		tempGroupMembers := []string{}
		//Get Group Members
		for _, members := range xx["members"].([]interface{}) {
			xy := members.(map[string]interface{})
			username := strings.Split(xy["userPrincipalName"].(string), "@")[0]
			tempGroupMembers = append(tempGroupMembers, username)
		}
		tempGroup.Members = tempGroupMembers
		tempGroup.Groupname = xx["displayName"].(string)
		tempGroup.Password = "x"
		tempGroup.GID = 100

		groupResult = append(groupResult, tempGroup)
	}

	return nss.StatusSuccess, groupResult
}

// GroupByName returns a group, not managed here
func (self LibNssOauth) GroupByName(name string) (nss.Status, nssStructs.Group) {

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
		return nss.StatusUnavail, []nssStructs.Shadow{}
	}

	//Build all users query. Filters users without licences and only returns required fields.
	getUserQuery := "v1.0/users?$filter=assignedLicenses/$count+ne+0&$count=true&$select=id,userPrincipalName,lastPasswordChangeDateTime"
	log.Println("Query: %s", getUserQuery) //DEBUG

	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		log.Println("MSGraph request failed:", err)
		return nss.StatusUnavail, []nssStructs.Shadow{}
	}

	//Open Slice/Struct for result
	shadowResult := []nssStructs.Shadow{}

	for _, userResult := range jsonOutput["value"].([]interface{}) {
		//Create temporary struct for user info
		tempUser := nssStructs.Shadow{}

		//Map value var to correct type to allow for access
		xx := userResult.(map[string]interface{})

		//Strip domain from UPN
		user := strings.Split(xx["userPrincipalName"].(string), "@")[0]

		//Set user info
		tempUser.Username = user
		tempUser.Password = "*"
		tempUser.PasswordWarn = 7
		log.Printf("Last Password Change: %s", xx["lastPasswordChangeDateTime"].(string))
		tempUser.LastChange = 19000
		//tempUser.LastChange = xx["lastPasswordChangeDateTime"]
		log.Println(tempUser)
		shadowResult = append(shadowResult, tempUser)
	}

	return nss.StatusSuccess, shadowResult
}

// ShadowByName return shadow entry, not managed as no password are allowed here
func (self LibNssOauth) ShadowByName(name string) (nss.Status, nssStructs.Shadow) {

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
		return nss.StatusUnavail, nssStructs.Shadow{}
	}

	//Build all users query, only returns required fields
	username := fmt.Sprintf(config.Domain, name)

	getUserQuery := "v1.0/users/" + username + "?$count=true&$select=id,userPrincipalName,lastPasswordChangeDateTime"
	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		log.Println("MSGraph request failed:", err)
		log.Println("HERE")
		return nss.StatusNotfound, nssStructs.Shadow{}
	}

	//Strip domain from UPN
	user := strings.Split(jsonOutput["userPrincipalName"].(string), "@")[0]

	//tempUser.LastChange = xx["lastPasswordChangeDateTime"]
	shadowResult := nssStructs.Shadow{Username: user, Password: "*", PasswordWarn: 7, LastChange: 19000, MinChange: 1, MaxChange: 365, ExpirationDate: 19500}
	log.Println(shadowResult)

	return nss.StatusSuccess, shadowResult
}
