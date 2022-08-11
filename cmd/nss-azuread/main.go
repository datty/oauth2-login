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
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/datty/pam-azuread/internal/conf"

	nss "github.com/protosam/go-libnss"
	nssStructs "github.com/protosam/go-libnss/structs"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// app name
const app = "nss-azuread"

//Root Checker
var isroot bool

// Placeholder main() stub is neccessary for compile.
func main() {}

func init() {
	// We set our implementation to "LibNssOauth", so that go-libnss will use the methods we create
	nss.SetImpl(LibNssOauth{})
}

// LibNssExternal creates a struct that implements LIBNSS stub methods.
type LibNssOauth struct{ nss.LIBNSS }

var config *conf.Config
var configsecret *conf.ConfigSecrets

//Random ID generator functions
func generateUniqueID(s []int, min int, max int) int {

	var uid int
	uniqueID := false

	//Check Min/Max values are valid
	if min == 0 || max == 0 {
		errorLog.Println("Min/Max range is not set. Using default range 10000-15000")
		min = 10000
		max = 15000
	}
	for uniqueID != true {
		rand.Seed(time.Now().UnixNano())
		uid = min + rand.Intn(max-min+1)
		if intContains(s, uid) == false {
			uniqueID = true
			debugLog.Println("UniqueID Gen is unique:", uid) //DEBUG
		}
	}
	return uid
}

//Find int in array of ints
func intContains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (self LibNssOauth) oauth_init() (result confidential.AuthResult, err error) {

	//Load config vars
	if config == nil {
		if config, err = conf.ReadConfig(); err != nil {
			errorLog.Println("unable to read configfile:", err)
			return result, err
		}
	}

	//Check if running as root, return RW access credentials if running as root and enable caching
	if os.Getuid() != 0 {
		isroot = false
		debugLog.Printf("AzureAD access is read only, running as unprivileged user")
	} else {
		isroot = true
		if configsecret == nil {
			if configsecret, err = conf.ReadSecrets(); err != nil {
				errorLog.Println("unable to read secretsfile:", err)
				return result, err
			}
		}
		//Set config vars from secrets if available
		config.ClientID = configsecret.ClientID
		config.ClientSecret = configsecret.ClientSecret
	}

	//Open OAuth
	cred, err := confidential.NewCredFromSecret(config.ClientSecret)
	if err != nil {
		errorLog.Println(err)
	}

	if isroot {
		//Enable oauth cred cache
		cacheAccessor := &TokenCache{"/var/tmp/" + app + "_" + fmt.Sprint(os.Getuid()) + "_.json"}
		app, err := confidential.New(config.ClientID, cred, confidential.WithAuthority("https://login.microsoftonline.com/"+config.TenantID), confidential.WithAccessor(cacheAccessor))
		if err != nil {
			errorLog.Println(err)
		}
		result, err = app.AcquireTokenSilent(context.Background(), config.NssScopes)
		if err != nil {
			result, err = app.AcquireTokenByCredential(context.Background(), config.NssScopes)
			if err != nil {
				errorLog.Println(err)
			}
			//infoLog.Println("Acquired Access Token " + result.AccessToken)
			debugLog.Println("Acquired Access Token")
			return result, err
		}
		debugLog.Println("Silently acquired token")
		return result, err
	} else {
		app, err := confidential.New(config.ClientID, cred, confidential.WithAuthority("https://login.microsoftonline.com/"+config.TenantID))
		if err != nil {
			errorLog.Println(err)
		}
		result, err = app.AcquireTokenByCredential(context.Background(), config.NssScopes)
		if err != nil {
			errorLog.Println(err)
		}
		//infoLog.Println("Acquired Access Token " + result.AccessToken)
		debugLog.Println("Acquired Access Token")
		return result, err
	}
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
		errorLog.Println(err)
	}

	jsonErr := json.Unmarshal([]byte(body), &output)
	if jsonErr != nil {
		errorLog.Println(err)
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
		debugLog.Println("Query:", getUIDQuery) //DEBUG
	} else {
		getUIDQuery = "v1.0" + getUIDQuery + config.UserUIDAttribute
		debugLog.Println("Query:", getUIDQuery) //DEBUG
	}
	jsonOutput, err := self.msgraph_req(t, getUIDQuery)
	if err != nil {
		errorLog.Println("MSGraph request failed:", err)
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
	newUID := uint(generateUniqueID(uidList, config.MinUID, config.MaxUID))

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
		debugLog.Println("Query:", getUIDQuery) //DEBUG

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
	} else {
		getUIDQuery = "v1.0" + getUIDQuery
		debugLog.Println("Query:", getUIDQuery) //DEBUG

		//Set JSON
		json = fmt.Sprintf(`{
			"%s": %d
		}`, config.UserUIDAttribute, uid)
	}

	_, err = self.msgraph_update(t, getUIDQuery, []byte(json))

	if err != nil {
		errorLog.Println("MSGraph request failed:", err)
		return 0, err
	}
	return uid, err

}

//Lookup existing GIDs and generate a unique GID
func (self LibNssOauth) GetUnusedGID(t string) (output uint, err error) {

	//Build all users query. Filters users without licences and only returns required fields.
	getGIDQuery := "v1.0/groups?$filter=securityEnabled+eq+true&$select=" + config.GroupGidAttribute
	debugLog.Println("Query:", getGIDQuery) //DEBUG
	jsonOutput, err := self.msgraph_req(t, getGIDQuery)
	if err != nil {
		errorLog.Println("MSGraph request failed:", err)
		return 0, err
	}

	//Create empty gidlist
	gidList := []int{}

	//Collect existing gids
	for _, groupResult := range jsonOutput["value"].([]interface{}) {
		//Map value var to correct type to allow for access
		xx := groupResult.(map[string]interface{})

		//Get GIDs
		if xx[config.GroupGidAttribute] != nil {
			gidList = append(gidList, int(xx[config.GroupGidAttribute].(float64)))
		}
	}
	newGID := uint(generateUniqueID(gidList, config.MinGID, config.MaxGID))

	return newGID, nil
}

//Get unusedGID from above function and then apply to AzureAD
func (self LibNssOauth) AutoSetGID(t string, groupid string) (gid uint, err error) {

	//Get Next Available UID
	gid, err = self.GetUnusedGID(t)
	if err != nil {
		return 0, err
	}

	//Build query and body to set GID
	var json string
	setGIDQuery := "v1.0/groups/" + groupid
	debugLog.Println("AutoSetGID Query:", setGIDQuery) //DEBUG
	//Set JSON
	json = fmt.Sprintf(`{
		"%s": %d
	}`, config.GroupGidAttribute, gid)
	debugLog.Println("AutoSetGID JSON:", json) //DEBUG
	_, err = self.msgraph_update(t, setGIDQuery, []byte(json))

	if err != nil {
		errorLog.Println("MSGraph request failed:", err)
		return 0, err
	}
	debugLog.Println("Set GID for: ", gid)
	return gid, err
}

// PasswdAll will populate all entries for libnss
func (self LibNssOauth) PasswdAll() (nss.Status, []nssStructs.Passwd) {

	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		errorLog.Println("Oauth Failed:", err)
		return nss.StatusUnavail, []nssStructs.Passwd{}
	}

	//Build all users query. Filters users without licences and only returns required fields.
	getUserQuery := "/users?$filter=assignedLicenses/$count+ne+0&$count=true&$select=id,displayName,userPrincipalName"
	if config.UseSecAttributes {
		//Uses 'beta' endpoint as customSecurityAttributes are only available there.
		getUserQuery = "beta" + getUserQuery + ",customSecurityAttributes"
		debugLog.Println("PasswdAll Query") //DEBUG
	} else {
		getUserQuery = "v1.0" + getUserQuery + "," + config.UserUIDAttribute + "," + config.UserGIDAttribute
		debugLog.Println("PasswdAll Query") //DEBUG
	}
	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		errorLog.Println("PasswdAll MSGraph request failed:", err)
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
					errorLog.Println("No CSA-AS") //DEBUG
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
		tempUser.Gecos = xx["displayName"].(string)
		tempUser.Dir = fmt.Sprintf("/home/%s", user)
		tempUser.Shell = "/bin/bash"

		//Add this user to result if no errors flagged
		if userUIDErr == true && config.UserAutoUID == true && isroot {
			//Do the magic and set UID
			tempUser.UID, err = self.AutoSetUID(result.AccessToken, xx["id"].(string))
			//AzureAD eventual consistency...Pause to prevent UID clash
			time.Sleep(5 * time.Second)
			debugLog.Println("UserID:", xx["id"].(string))
			debugLog.Println("User:", xx["userPrincipalName"].(string))
			debugLog.Println("New UID:", tempUser.UID)
		} else if userUIDErr == true && config.UserAutoUID == false {
			//Return nobody UID if autoUID is disabled
			tempUser.UID = 65534
		}
		passwdResult = append(passwdResult, tempUser)
	}

	return nss.StatusSuccess, passwdResult
}

// PasswdByName returns a single entry by name.
func (self LibNssOauth) PasswdByName(name string) (nss.Status, nssStructs.Passwd) {

	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		errorLog.Println("Oauth Failed:", err)
		return nss.StatusUnavail, nssStructs.Passwd{}
	}

	//Build all users query, only returns required fields
	username := fmt.Sprintf(config.Domain, name)

	getUserQuery := "/users/" + username + "?$count=true&$select=id,displayName,userPrincipalName"
	if config.UseSecAttributes {
		//Uses 'beta' endpoint as customSecurityAttributes are only available there.
		getUserQuery = "beta" + getUserQuery + ",customSecurityAttributes"
		debugLog.Println("PasswdByName Query:", username) //DEBUG
	} else {
		getUserQuery = "v1.0" + getUserQuery + "," + config.UserUIDAttribute + "," + config.UserGIDAttribute
		debugLog.Println("PasswdByName Query:", username) //DEBUG
	}
	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		errorLog.Println("PasswdByName MSGraph request failed:", err)
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
				errorLog.Println("No CSA-AS") //DEBUG
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
	passwdResult.Gecos = jsonOutput["displayName"].(string)
	passwdResult.Dir = fmt.Sprintf("/home/%s", user)
	passwdResult.Shell = "/bin/bash"

	//Add this user to result if no errors flagged
	if userUIDErr == true && config.UserAutoUID == true && isroot {
		//Do the magic and set UID
		passwdResult.UID, err = self.AutoSetUID(result.AccessToken, jsonOutput["id"].(string))
		debugLog.Println("UserID:", jsonOutput["id"].(string))              //DEBUG
		debugLog.Println("User:", jsonOutput["userPrincipalName"].(string)) //DEBUG
		debugLog.Println("New UID:", passwdResult.UID)                      //DEBUG
	} else if userUIDErr == true && config.UserAutoUID == false {
		return nss.StatusNotfound, nssStructs.Passwd{}
	}

	return nss.StatusSuccess, passwdResult
}

// PasswdByUid returns a single entry by uid, not managed here
func (self LibNssOauth) PasswdByUid(uid uint) (nss.Status, nssStructs.Passwd) {

	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		errorLog.Println("Oauth Failed:", err)
		return nss.StatusUnavail, nssStructs.Passwd{}
	}

	getUserQuery := "/users/?$count=true&$select=id,displayName,userPrincipalName"
	if config.UseSecAttributes {
		//Uses 'beta' endpoint as customSecurityAttributes are only available there.
		getUserQuery = "beta" + getUserQuery + ",customSecurityAttributes&$filter=customSecurityAttributes/" + config.AttributeSet + "/" + config.UserUIDAttribute + "+eq+" + fmt.Sprintf("%d", uid)
		debugLog.Println("PasswdByUid Query:", uid) //DEBUG
	} else {
		getUserQuery = "v1.0" + getUserQuery + "," + config.UserUIDAttribute + "," + config.UserGIDAttribute + "&$filter=" + config.UserUIDAttribute + "+eq+" + fmt.Sprintf("%d", uid)
		debugLog.Println("PasswdByUid Query:", uid) //DEBUG
	}
	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		errorLog.Println("PasswdByUid MSGraph request failed:", err)
		return nss.StatusNotfound, nssStructs.Passwd{}
	}

	//Parse jsonOutput to something usable...
	xx := jsonOutput["value"].([]interface{})
	if len(xx) != 0 {
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
		passwdResult.Gecos = xy["displayName"].(string)
		passwdResult.Dir = fmt.Sprintf("/home/%s", user)
		passwdResult.Shell = "/bin/bash"

		return nss.StatusSuccess, passwdResult
	} else {
		return nss.StatusNotfound, nssStructs.Passwd{}
	}
}

// GroupAll returns all groups
func (self LibNssOauth) GroupAll() (nss.Status, []nssStructs.Group) {
	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		errorLog.Println("Oauth Failed:", err)
		return nss.StatusUnavail, []nssStructs.Group{}
	}

	//Build all groups query. Filters for groups where GID is set and the group is a security group
	getGroupQuery := "v1.0/groups?$count=true&$filter=securityEnabled+eq+true&$expand=members($select=id,userPrincipalName)&$select=id,displayName," + config.GroupGidAttribute
	debugLog.Println("GroupAll Query") //DEBUG
	jsonOutput, err := self.msgraph_req(result.AccessToken, getGroupQuery)
	if err != nil {
		errorLog.Println("GroupAll MSGraph request failed:", err)
		return nss.StatusUnavail, []nssStructs.Group{}
	}

	//Open Slice/Struct for result
	groupResult := []nssStructs.Group{}

	for _, grpresult := range jsonOutput["value"].([]interface{}) {
		//Create temporary struct for group info
		tempGroup := nssStructs.Group{}

		//Map value var to correct type to allow for access
		xx := grpresult.(map[string]interface{})
		tempGroupMembers := []string{}
		//Get Group Members
		for _, members := range xx["members"].([]interface{}) {
			xy := members.(map[string]interface{})
			if xy["userPrincipalName"] != nil {
				username := strings.Split(xy["userPrincipalName"].(string), "@")[0]
				tempGroupMembers = append(tempGroupMembers, username)
			}
		}
		tempGroup.Members = tempGroupMembers
		tempGroup.Groupname = xx["displayName"].(string)
		tempGroup.Password = "x"
		if xx[config.GroupGidAttribute] != nil {
			tempGroup.GID = uint(xx[config.GroupGidAttribute].(float64))
			groupResult = append(groupResult, tempGroup)
		} else if xx[config.GroupGidAttribute] == nil && config.GroupAutoGID == true && isroot {
			tempGroup.GID, err = self.AutoSetGID(result.AccessToken, xx["id"].(string))
			groupResult = append(groupResult, tempGroup)
		}
	}

	return nss.StatusSuccess, groupResult
}

// GroupByName returns a group, not managed here
func (self LibNssOauth) GroupByName(name string) (nss.Status, nssStructs.Group) {
	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		errorLog.Println("Oauth Failed:", err)
		return nss.StatusUnavail, nssStructs.Group{}
	}

	groupName := url.QueryEscape(name)
	//Search for group by display name, simple query due to MS Graph 400
	getGroupQuery := "v1.0/groups?$filter=securityEnabled+eq+true&$select=id,displayName&$search=\"displayName:" + groupName + "\""
	debugLog.Println("GroupByName Query:", getGroupQuery) //DEBUG
	jsonOutput, err := self.msgraph_req(result.AccessToken, getGroupQuery)
	if err != nil {
		errorLog.Println("MSGraph request failed:", err)
		return nss.StatusUnavail, nssStructs.Group{}
	}

	//Open Slice/Struct for result
	groupResult := nssStructs.Group{}

	//Loop through matching search results
	for _, value := range jsonOutput["value"].([]interface{}) {
		//Map value var to correct type to allow for access
		xx := value.(map[string]interface{})
		//Check for exact match on name
		if xx["displayName"].(string) == name {
			//Lookup this group and get all info
			ActualGroupQuery := "v1.0/groups/" + xx["id"].(string) + "?$expand=members($select=id,userPrincipalName)&$select=id,displayName," + config.GroupGidAttribute
			debugLog.Println("GroupByName Specific Query:", xx["id"].(string)) //DEBUG
			groupOutput, err := self.msgraph_req(result.AccessToken, ActualGroupQuery)
			if err != nil {
				log.Println("MSGraph request failed:", err)
				return nss.StatusUnavail, nssStructs.Group{}
			}
			tempGroupMembers := []string{}
			//Get Group Members
			for _, members := range groupOutput["members"].([]interface{}) {
				xy := members.(map[string]interface{})
				if xy["userPrincipalName"] != nil {
					username := strings.Split(xy["userPrincipalName"].(string), "@")[0]
					tempGroupMembers = append(tempGroupMembers, username)
				}
			}
			groupResult.Members = tempGroupMembers
			groupResult.Groupname = groupOutput["displayName"].(string)
			groupResult.Password = "x"
			if groupOutput[config.GroupGidAttribute] != nil {
				groupResult.GID = uint(groupOutput[config.GroupGidAttribute].(float64))
				return nss.StatusSuccess, groupResult
			} else if groupOutput[config.GroupGidAttribute] == nil && config.GroupAutoGID == true && isroot {
				groupResult.GID, err = self.AutoSetGID(result.AccessToken, groupOutput["id"].(string))
				return nss.StatusSuccess, groupResult
			}
		}
	}
	return nss.StatusNotfound, groupResult

}

// GroupBuGid retusn group by id, not managed here
func (self LibNssOauth) GroupByGid(gid uint) (nss.Status, nssStructs.Group) {
	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		errorLog.Println("Oauth Failed:", err)
		return nss.StatusUnavail, nssStructs.Group{}
	}

	//Search for group by GID
	getGroupQuery := "v1.0/groups?$count=true&$expand=members($select=id,userPrincipalName)&$select=id,displayName," + config.GroupGidAttribute + "&$filter=" + config.GroupGidAttribute + "+eq+" + fmt.Sprint(gid) + "+and+securityEnabled+eq+true"
	debugLog.Println("GroupByGid Query:", gid) //DEBUG
	jsonOutput, err := self.msgraph_req(result.AccessToken, getGroupQuery)
	if err != nil {
		log.Println("GroupByGid MSGraph request failed:", err)
		return nss.StatusUnavail, nssStructs.Group{}
	}

	//Open Slice/Struct for result
	groupResult := nssStructs.Group{}

	//Parse jsonOutput to something usable...
	xx := jsonOutput["value"].([]interface{})
	if len(xx) != 0 {
		xy := xx[0].(map[string]interface{})
		tempGroupMembers := []string{}
		//Get Group Members
		for _, members := range xy["members"].([]interface{}) {
			xz := members.(map[string]interface{})
			if xz["userPrincipalName"] != nil {
				username := strings.Split(xz["userPrincipalName"].(string), "@")[0]
				tempGroupMembers = append(tempGroupMembers, username)
			}
		}
		groupResult.Members = tempGroupMembers
		groupResult.Groupname = xy["displayName"].(string)
		groupResult.Password = "x"
		groupResult.GID = uint(xy[config.GroupGidAttribute].(float64))
		return nss.StatusSuccess, groupResult
	}
	return nss.StatusNotfound, groupResult
}

// ShadowAll return all shadow entries, not managed as no password are allowed here
func (self LibNssOauth) ShadowAll() (nss.Status, []nssStructs.Shadow) {
	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		errorLog.Println("Oauth Failed:", err)
		return nss.StatusUnavail, []nssStructs.Shadow{}
	}

	//Build all users query. Filters users without licences and only returns required fields.
	getUserQuery := "v1.0/users?$filter=assignedLicenses/$count+ne+0&$count=true&$select=id,userPrincipalName,lastPasswordChangeDateTime"
	debugLog.Println("ShadowAll Query") //DEBUG

	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		log.Println("ShadowAll MSGraph request failed:", err)
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
		lastpasschange, _ := time.Parse(time.RFC3339, xx["lastPasswordChangeDateTime"].(string))
		tempUser.LastChange = int(lastpasschange.Unix() / 86400)
		tempUser.ExpirationDate = 99999
		tempUser.MaxChange = 99999
		shadowResult = append(shadowResult, tempUser)
	}

	return nss.StatusSuccess, shadowResult
}

// ShadowByName return shadow entry, not managed as no password are allowed here
func (self LibNssOauth) ShadowByName(name string) (nss.Status, nssStructs.Shadow) {
	//Get OAuth token
	result, err := self.oauth_init()
	if err != nil {
		errorLog.Println("Oauth Failed:", err)
		return nss.StatusUnavail, nssStructs.Shadow{}
	}

	//Build all users query, only returns required fields
	username := fmt.Sprintf(config.Domain, name)

	getUserQuery := "v1.0/users/" + username + "?$count=true&$select=id,userPrincipalName,lastPasswordChangeDateTime"
	debugLog.Println("ShadowByName Query:", username) //DEBUG

	jsonOutput, err := self.msgraph_req(result.AccessToken, getUserQuery)
	if err != nil {
		errorLog.Println("ShadowByName MSGraph request failed:", err)
		return nss.StatusNotfound, nssStructs.Shadow{}
	}

	//Strip domain from UPN
	user := strings.Split(jsonOutput["userPrincipalName"].(string), "@")[0]
	lastpasschange, _ := time.Parse(time.RFC3339, jsonOutput["lastPasswordChangeDateTime"].(string))
	shadowResult := nssStructs.Shadow{Username: user, Password: "*", PasswordWarn: 7, LastChange: int(lastpasschange.Unix() / 86400), MinChange: 0, MaxChange: 99999, ExpirationDate: 99999}

	return nss.StatusSuccess, shadowResult
}
