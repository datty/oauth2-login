# pam-azuread

This PAM module allows for authentication against AzureAD using the Microsoft Authentication Library. 

This is based on work in the following repos:
- https://github.com/shimt/pam-exec-oauth2
- https://github.com/metal-stack/pam-exec-oauth2

## Install

```bash
make

sudo make install
```

## Configuration

### PAM

add the following lines to `/etc/pam.d/common-auth`

```
#### authenticate with azuread flow #####
auth sufficient pam_azuread.so
```

### NSS

add `azuread` to the `passwd:` line in `/etc/nsswitch.conf` like this:

```
# /etc/nsswitch.conf

passwd:         files systemd azuread
```

### azuread.conf

Configuration must be stored in `/etc/azuread.conf`. There is no option to change the location
of this config file. Example:

#### Azure AD

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

#### Config options
- `custom-security-attributes`: Uses AzureAD custom security attributes for storing user UID/GID.
    - `attribute-set`: The custom security attribute set which contains UIDs/GIDs. This must be created manually using the AzureAD AAD console
- `user-uid-attribute-name`: The attribute to lookup which will contain the user UID
- `user-gid-attribute-name`: The attribute to lookup which will contain the user GID
- `user-auto-uid`: Enable automatic creation of user UIDs. Where no UID is set the uid-range-min and uid-range-max values will be used to find a unique ID within this range
- `group-auto-gid`: Enable automatic creation of group GIDs. Where no GID is set the gid-range-min and gid-range-max values will be used to find a unique ID within this range

#### Azure AD Setup
Quickly noting group GID attribute setup.

As AzureAD does not have UID/GIDs, we have to use custom attributes to add these values. For Users we can use custom security attributes, but for groups this functionality is not yet available. To add GIDs to group objects we need to register an application directory extension to create the GID property. This can be done using a POST request as follows:

POST https://graph.microsoft.com/v1.0/applications/${APPLICATION OBJECT ID}/extensionProperties
Headers:
- Authorization = Bearer ${AzureADToken}
Body:
{
    "name": "GID",
    "dataType": "Integer",
    "targetObjects": [
        "Group"
    ]
}

The response will contain the property name which should be in the form of extension_UUID_GID. Use this value for the group-gid-attribute-name setting in the azuread.conf file.