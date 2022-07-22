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

### oauth2-login.config

Configuration must be stored in `/etc/azuread.conf`. There is no option to change the location
of this config file. Example:

#### Azure AD

```yaml
---
client-id: "xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client-secret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
redirect-url: "urn:ietf:wg:oauth:2.0:oob"
scopes: 
    - "email"
    - "openid"
tenant-id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
o365-domain: "%s@example.org"
createuser: true
sufficient-roles: 
    - "serverAccess"
allowed-roles: 
    - "wheel"
```

#### Config options

- `createuser`: Enable user account autocreation.
- `sufficient-roles`: User must have these roles assigned to login.
- `allowed-roles`: If a user has these roles, they will be assigned to his Unix user as groups.
  All other roles will be ignored.
