# pam-azuread

This PAM module allows for authentication against AzureAD using the Microsoft Authentication Library. 

This is based on work in the following repos:
- https://github.com/shimt/pam-exec-oauth2
- https://github.com/metal-stack/pam-exec-oauth2

Due to lookup speeds and some outstanding issues on group lookup, this module must be used with NSCD.

## Install

```bash
make

sudo make install
```

## Configuration

### PAM

Update the following lines in `/etc/pam.d/common-auth`

```
#### authenticate with azuread flow #####
# here are the per-package modules (the "Primary" block)
auth    [success=2 default=ignore]      pam_unix.so nullok
auth    [success=1 default=ignore]      pam_azuread.so
```

### NSS

add `azuread` to the `passwd:`, `group:`, and `shadow:` lines in `/etc/nsswitch.conf` like this:

```
# /etc/nsswitch.conf
passwd:         files systemd azuread
group:          files systemd azuread
shadow:         files azuread
```

### azuread.conf

Configuration must be stored in `/etc/azuread.conf` and `/etc/azuread-secret.conf`. There is no option to change the location
of this config file. Example:

#### Sample azuread.conf

```yaml
---
client-id: "xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client-secret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
redirect-url: "urn:ietf:wg:oauth:2.0:oob"
pam-scopes: 
    - "email"
    - "openid"
nss-scopes:
    - "https://graph.microsoft.com/.default"
    - "openid"
tenant-id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
o365-domain: "%s@example.org"
custom-security-attributes: true
attribute-set: "RFC2307"
user-uid-attribute-name: "UID"
user-gid-attribute-name: "GID"
user-gid-default: 100
user-auto-uid: true
uid-range-min: 10000
uid-range-max: 15000
group-gid-attribute-name: "extension_UUIDX_GID"
group-auto-gid: true
gid-range-min: 1000
gid-range-max: 1200
```

#### Sample azuread-secret.conf

```yaml
---
client-id: "xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client-secret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

#### Config options
- `custom-security-attributes`: Uses AzureAD custom security attributes for storing user UID/GID.
    - `attribute-set`: The custom security attribute set which contains UIDs/GIDs. This must be created manually using the AzureAD AAD console
- `user-uid-attribute-name`: The attribute to lookup which will contain the user UID
- `user-gid-attribute-name`: The attribute to lookup which will contain the user GID
- `user-auto-uid`: Enable automatic creation of user UIDs. Where no UID is set the uid-range-min and uid-range-max values will be used to find a unique ID within this range
- `group-auto-gid`: Enable automatic creation of group GIDs. Where no GID is set the gid-range-min and gid-range-max values will be used to find a unique ID within this range

#### Azure AD Setup
1. Create a new App Registration in your Azure Active Directory Admin Center. Name the application 'Azure Desktop Login' or similar.
2. Under the Authentication section, enable 'Allow public client flows'.
3. Under the Certificates & Secrets -> Client secrets, select New client secret. Set a description and A validity period. When the client secret is created, copy the value to the /etc/azuread-secret.conf file client-secret setting.
4. Under API Permissions, add the following Application permissions
 * CustomSecAttributeAssignment.ReadWrite.All - Only required if using Custom Security Attributes
 * CustomSecAttributeDefinition.Read.All - Only required if using Custom Security Attributes
 * Group.ReadWrite.All
 * User.Read.All - If not using Custom Security Attributes, change this permission to User.ReadWrite.All
5. Under API Permissions, add the following delegated permissions
 * email
 * openid
6. Under API Permissions, click 'Grant Admin consent' for the selected permissions
7. From the Overview page:
 * Copy the 'Application (client) ID' to the azuread-secret.conf file as the client-id
8. Create a second App Registration in your Azure Active Directory Admin Center. Name the application 'Azure Desktop Login - Unprivileged' or similar
9. Under the Authentication section, enable 'Allow public client flows'.
10. Under the Certificates & Secrets -> Client secrets, select New client secret. Set a description and A validity period. When the client secret is created, copy the value to the /etc/azuread.conf file client-secret setting.
11. Under API Permissions, add the following Application permissions
 * CustomSecAttributeAssignment.Read.All - Only required if using Custom Security Attributes
 * CustomSecAttributeDefinition.Read.All - Only required if using Custom Security Attributes
 * Group.Read.All
 * User.Read.All
12. Under API Permissions, click 'Grant Admin consent' for the selected permissions
13. From the Overview page:
 *  Copy the 'Application (client) ID' to the azuread.conf file as the client-id
 *  Copy the 'Directory (tenant) ID' to the azuread.conf file as the tenant-id

#### Custom Attribute Setup
As AzureAD does not have UID/GIDs, we have to use custom attributes to add these values. 

For users, we can use Custom Security Attributes, or an application directory extension.
For groups, Custom Security Attributes are not available and we must use an application directory extension.

##### Custom Security Attribute Setup

To setup custom security attributes for User UID/GIDs:
1. Go to the Azure Active Directory Admin Center and select Custom Security Attributes
2. Add an attribute set, for example 'RFC2307'. Enter the same value in the azuread.conf file attribute-set setting
3. Open the newly created attribute set and add the required attributes:
 * Attribute Name: UID, Data Type: Integer. Add the attribute name set here in the azuread.conf file user-uid-attribute-name setting
 * Attribute Name: GID, Data Type: Integer. Add the attribute name set here in the azuread.conf file user-gid-attribute-name setting

##### Application Directory Extension Setup (User)

To setup an Application Directory Extension for User UIDs/GIDs (optional if you have chosen Custom Security Attributes above)

1. Register an application directory extension to create the UID property. This can be done using a POST request as follows (The Application Object ID can be found on the overview page of the Application created in step 1 above):

``` POST https://graph.microsoft.com/v1.0/applications/${APPLICATION OBJECT ID}/extensionProperties
Headers:
- Authorization = Bearer ${AzureADToken}
Body:

{
    "name": "UserUID",
    "dataType": "Integer",
    "targetObjects": [
        "Group"
    ]
}
```
The response will contain the property name which should be in the form of extension_UUID_UserUID. Use this value for the user-uid-attribute-name setting in the azuread.conf file.

2. Register an application directory extension to create the GID property. This can be done using a POST request as follows (The Application Object ID can be found on the overview page of the Application created in step 1 above):

``` POST https://graph.microsoft.com/v1.0/applications/${APPLICATION OBJECT ID}/extensionProperties
Headers:
- Authorization = Bearer ${AzureADToken}
Body:

{
    "name": "UserGID",
    "dataType": "Integer",
    "targetObjects": [
        "Group"
    ]
}
```
The response will contain the property name which should be in the form of extension_UUID_UserGID. Use this value for the user-uid-attribute-name setting in the azuread.conf file.

##### Application Directory Extension Setup (Group)

To add GIDs to group objects we need to register an application directory extension to create the GID property. This can be done using a POST request as follows:
```
POST https://graph.microsoft.com/v1.0/applications/${APPLICATION OBJECT ID}/extensionProperties
Headers:
- Authorization = Bearer ${AzureADToken}
Body:
{
    "name": "GroupGID",
    "dataType": "Integer",
    "targetObjects": [
        "Group"
    ]
}
```
The response will contain the property name which should be in the form of extension_UUID_GroupGID. Use this value for the group-gid-attribute-name setting in the azuread.conf file.