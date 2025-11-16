# Technitium DNS Server API Documentation

Technitium DNS Server provides a HTTP API which is used by the web console to perform all actions. Thus any action that the web console does can be performed using this API from your own applications.

The URL in the documentation uses `localhost` and port `5380`. You should use the hostname/IP address and port that is specific to your DNS server instance.

## API Request

Unless it is explicitly specified, all HTTP API requests can use both `GET` or `POST` methods. When using `POST` method to pass the API parameters as form data, the `Content-Type` header must be set to `application/x-www-form-urlencoded`. When the HTTP API call is used to upload files, the call must use `POST` method and the `Content-Type` header must be set to `multipart/form-data`.

Note! The "set" type of API requests will overwrite any existing value managed by that call. The "add" type of API requests will append to existing value managed by the call.

## API Response Format

The HTTP API returns a JSON formatted response for all requests. The JSON object returned contains `status` property which indicate if the request was successful. 

The `status` property can have following values:
- `ok`: This indicates that the call was successful.
- `error`: This response tells the call failed and provides additional properties that provide details about the error.
- `invalid-token`: When a session has expired or an invalid token was provided this response is received.
- `2fa-required`: When a user has two-factor authentication enabled and the OTP was not provided during login, change password, etc. API calls.

A successful response will look as shown below. Note that there will be other properties in the response which are specific to the request that was made.

```
{
	"status": "ok"
}
```

In case of errors, the response will look as shown below. The `errorMessage` property can be shown in the UI to the user while the other two properties are useful for debugging.

```
{
	"status": "error",
	"errorMessage": "error message",
	"stackTrace": "application stack trace",
	"innerErrorMessage": "inner exception message"
}
```

## Name Server Address Format

The DNS server uses a specific text format to define the name server address to allow specifying multiple parameters like the domain name, IP address, port or URL. This format is used in the web console as well as in this API. It is used to specify forwarder address in DNS settings, conditional forwarder zone's FWD record, or the server address in DNS Client resolve query API calls.

- A name server address with just an IP address is specified just as its string literal with optional port number is as shown: `1.1.1.1` or `8.8.8.8:53`. When port is not specified, the default port number for the selected DNS transport protocol is used.
- A name server address with just a domain name is specified similarly as its string literal with optional port number is as shown: `dns.quad9.net:853` or `cloudflare-dns.com`. When port is not specified, the default port number for the selected DNS transport protocol is used.
- A combination of domain name and IP address together with optional port number is as shown: `cloudflare-dns.com (1.1.1.1)`, `dns.quad9.net (9.9.9.9:853)` or `dns.quad9.net:853 (9.9.9.9)`. Here, the domain name (with optional port number) is specified and the IP address (with optional port number) is specified in a round bracket. When port is not specified, the default port number for the selected DNS transport protocol is used. This allows the DNS server to use the specified IP address instead of trying to resolve it separately.
- A name server address that specifies a DNS-over-HTTPS URL is specified just as its string literal is as shown: `https://cloudflare-dns.com/dns-query`
- A combination of DNS-over-HTTPS URL and IP address together is as shown: `https://cloudflare-dns.com/dns-query (1.1.1.1)`. Here, the IP address of the domain name in the URL is specified in the round brackets. This allows the DNS server to use the specified IP address instead of trying to resolve it separately.
- IPv6 addresses must always be enclosed in square brackets when port is specified as shown: `cloudflare-dns.com ([2606:4700:4700::1111]:853)` or `[2606:4700:4700::1111]:853`

## User API Calls

These API calls allow to a user to login, logout, perform account management, etc. Once logged in, a session token is returned which MUST be used with all other API calls.

### Login

This call authenticates with the server and generates a session token to be used for subsequent API calls. The session token expires as per the user's session expiry timeout value (default 30 minutes) from the last API call.

URL:\
`http://localhost:5380/api/user/login?user=admin&pass=admin&includeInfo=true`

OBSOLETE PATH:\
`/api/login`

PERMISSIONS:\
None

WHERE:
- `user`: The username for the user account. The built-in administrator username on the DNS server is `admin`.
- `pass`: The password for the user account. The default password for `admin` user is `admin`. 
- `totp` (optional): The time-based one-time password for the user account if it has Two Factor Authentication (2FA) enabled.
- `includeInfo` (optional): Includes basic info relevant for the user in response.

WARNING: It is highly recommended to change the password on first use to avoid security related issues.

RESPONSE:
```
{
	"displayName": "Administrator",
	"username": "admin",
	"totpEnabled": false,
	"token": "932b2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b698e9",
	"info": {
		"version": "14.0",
		"dnsServerDomain": "server1",
		"defaultRecordTtl": 3600,
		"permissions": {
			"Dashboard": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Zones": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Cache": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Allowed": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Blocked": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Apps": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"DnsClient": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Settings": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"DhcpServer": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Administration": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Logs": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		}
	},
	"status": "ok"
}
```

WHERE:
- `token`: Is the session token generated that MUST be used with all subsequent API calls.

### Create API Token

Allows creating a non-expiring API token that can be used with automation scripts to make API calls. The token allows access to API calls with the same privileges as that of the user account. Thus its recommended to create a separate user account with limited permissions as required by the specific task that the token will be used for. The token cannot be used to change the user's password, or update the user profile details.

URL:\
`http://localhost:5380/api/user/createToken?user=admin&pass=admin&tokenName=MyToken1`

PERMISSIONS:\
None

WHERE:
- `user`: The username for the user account for which to generate the API token.
- `pass`: The password for the user account.
- `totp` (optional): The time-based one-time password for the user account if it has Two Factor Authentication (2FA) enabled.
- `tokenName`: The name of the created token to identify its session.

RESPONSE:
```
{
	"username": "admin",
	"tokenName": "MyToken1",
	"token": "932b2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b698e9",
	"status": "ok"
}
```

WHERE:
- `token`: Is the session token generated that MUST be used with all subsequent API calls.

### Logout

This call ends the session generated by the `login` or the `createToken` call. The `token` would no longer be valid after calling the `logout` API.

URL:\
`http://localhost:5380/api/user/logout?token=932b2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b698e9`

OBSOLETE PATH:\
`/api/logout`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Get Session Info

Returns the same info as that of the `login` or the `createToken` calls for the session specified by the token.

URL:\
`http://localhost:5380/api/user/session/get?token=932b2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b698e9`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"displayName": "Administrator",
	"username": "admin",
	"totpEnabled": false,
	"token": "932b2a3495852c15af01598f62563ae534460388b6a370bfbbb8bb6094b698e9",
	"info": {
		"version": "14.0",
		"uptimestamp": "2023-07-29T08:01:31.1117463Z",
		"dnsServerDomain": "server1.example.com",
		"clusterInitialized": true,
		"clusterDomain": "example.com"
		"defaultRecordTtl": 3600,
		"useSoaSerialDateScheme": false,
		"dnssecValidation": true,
		"permissions": {
			"Dashboard": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Zones": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Cache": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Allowed": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Blocked": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Apps": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"DnsClient": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Settings": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"DhcpServer": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Administration": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			"Logs": {
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		}
	},
	"status": "ok"
}
```

### Delete User Session

Allows deleting a session for the current user.

URL:\
`http://localhost:5380/api/user/session/delete?token=x&partialToken=620c3bfcd09d0a07`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `partialToken`: The partial token as returned by the user profile details API call.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Change Password

Allows changing the password for the current logged in user account.

NOTE: It is highly recommended to change the `admin` user password on first use to avoid security related issues.

URL:\
`http://localhost:5380/api/user/changePassword?token=x&pass=password&newPass=newpassword`

OBSOLETE PATH:\
`/api/changePassword`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated only by the `login` call.
- `pass`: The current password for the currently logged in user.
- `newPass`: The new password to be set for the currently logged in user.
- `totp` (optional): The 6-digit code from the authenticator app if the user has 2FA enabled.
- `iterations` (optional): The number of iterations for PBKDF2 SHA256 password hashing.

RESPONSE:
```
{
	"status": "ok"
}
```

### Initialize 2FA

Initializes two-factor authentication for the current logged in user account. The secret returned by this API call needs to be used with authenticator apps like microsoft Authenticator or Google Authenticator. This call is the first step to enable 2FA followed by calling the Enable 2FA API call.

URL:\
`http://localhost:5380/api/user/2fa/init?token=x`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated only by the `login` call.

RESPONSE:
```
{
	"response": {
		"totpEnabled": false,
		"qrCodePngImage": "iVBORw0KGgoAAAANSUhEU...",
		"secret": "RZ56CYOXKAXI5D23"
	},
	"status": "ok"
}
```

### Enable 2FA

Enables two-factor authentication for the current logged in user account. This API call can be called only after the Initialize 2FA API call.

URL:\
`http://localhost:5380/api/user/2fa/enable?token=x`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated only by the `login` call.
- `totp`: The 6-digit code from the authenticator app.

RESPONSE:
```
{
	"status": "ok"
}
```

### Disable 2FA

Disables two-factor authentication for the current logged in user account.

URL:\
`http://localhost:5380/api/user/2fa/disable?token=x`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated only by the `login` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Get User Profile Details

Gets the user account profile details.

URL:\
`http://localhost:5380/api/user/profile/get?token=x`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"displayName": "Administrator",
		"username": "admin",
		"totpEnabled": false,
		"disabled": false,
		"previousSessionLoggedOn": "2022-09-15T12:59:05.944Z",
		"previousSessionRemoteAddress": "127.0.0.1",
		"recentSessionLoggedOn": "2022-09-15T13:57:50.1843973Z",
		"recentSessionRemoteAddress": "127.0.0.1",
		"sessionTimeoutSeconds": 1800,
		"memberOfGroups": [
			"Administrators"
		],
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": true,
				"partialToken": "620c3bfcd09d0a07",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-15T13:58:02.4728Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		]
	},
	"status": "ok"
}
```

### Set User Profile Details

Allows changing user account profile values.

URL:\
`http://localhost:5380/api/user/profile/set?token=x&displayName=Administrator&sessionTimeoutSeconds=1800`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated only by the `login` call.
- `displayName` (optional): The display name to set for the user account.
- `sessionTimeoutSeconds` (optional): The session timeout value to set in seconds for the user account.

RESPONSE:
```
{
	"response": {
		"displayName": "Administrator",
		"username": "admin",
		"totpEnabled": false,
		"disabled": false,
		"previousSessionLoggedOn": "2022-09-15T12:59:05.944Z",
		"previousSessionRemoteAddress": "127.0.0.1",
		"recentSessionLoggedOn": "2022-09-15T13:57:50.1843973Z",
		"recentSessionRemoteAddress": "127.0.0.1",
		"sessionTimeoutSeconds": 1800,
		"memberOfGroups": [
			"Administrators"
		],
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": true,
				"partialToken": "620c3bfcd09d0a07",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-15T14:00:50.288738Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		]
	},
	"status": "ok"
}
```

### Check For Update

This call requests the server to check for software update.

URL:\
`http://localhost:5380/api/user/checkForUpdate?token=x`

OBSOLETE PATH:\
`/api/checkForUpdate`

PERMISSIONS:\
None

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"updateAvailable": true,
		"updateVersion": "9.0",
		"currentVersion": "8.1.4",
		"updateTitle": "New Update Available!",
		"updateMessage": "Follow the instructions from the link below to update the DNS server to the latest version. Read the change logs before installing the update to know if there are any breaking changes.",
		"downloadLink": "https://download.technitium.com/dns/DnsServerSetup.zip",
		"instructionsLink": "https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html",
		"changeLogLink": "https://github.com/TechnitiumSoftware/DnsServer/blob/master/CHANGELOG.md"
	},
	"status": "ok"
}
```

## Dashboard API Calls

These API calls provide access to dashboard stats and allow deleting stat files.

### Get Stats

Returns the DNS stats that are displayed on the web console dashboard.

URL:\
`http://localhost:5380/api/dashboard/stats/get?token=x&type=LastHour&utc=true`

OBSOLETE PATH:\
`api/getStats`

PERMISSIONS:\
Dashboard: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node`: The node domain name for which the stats data is needed. When unspecified, the current node is used. Set node name as `cluster` to get aggregate stats for the entire cluster. This parameter can be used only when Clustering is initialized.
- `type` (optional): The duration type for which valid values are: [`LastHour`, `LastDay`, `LastWeek`, `LastMonth`, `LastYear`, `Custom`]. Default value is `LastHour`.
- `utc` (optional): Set to `true` to return the main chart data with labels in UTC date time format using which the labels can be converted into local time for display using the received `labelFormat`.
- `dontTrimQueryTypeData` (optional): Set to `true` to get full data for query type chart instead of top 10 entries. Default value is `false` when unspecified.
- `start` (optional): The start date in ISO 8601 format. Applies only to `custom` type.
- `end` (optional): The end date in ISO 8601 format. Applies only to `custom` type.

RESPONSE:
```
{
	"response": {
		"stats": {
			"totalQueries": 925,
			"totalNoError": 834,
			"totalServerFailure": 1,
			"totalNxDomain": 90,
			"totalRefused": 0,
			"totalAuthoritative": 47,
			"totalRecursive": 348,
			"totalCached": 481,
			"totalBlocked": 49,
			"totalDropped": 0,
			"totalClients": 6,
			"zones": 19,
			"cachedEntries": 6330,
			"allowedZones": 10,
			"blockedZones": 1,
			"allowListZones": 0,
			"blockListZones": 307447
		},
		"mainChartData": {
			"labelFormat": "HH:mm",
			"labels": [
				"2024-02-04T10:38:00.0000000Z",
				"2024-02-04T10:39:00.0000000Z",
				"2024-02-04T10:40:00.0000000Z",
				"2024-02-04T10:41:00.0000000Z",
				"2024-02-04T10:42:00.0000000Z",
				"2024-02-04T10:43:00.0000000Z",
				"2024-02-04T10:44:00.0000000Z",
				"2024-02-04T10:45:00.0000000Z",
				"2024-02-04T10:46:00.0000000Z",
				"2024-02-04T10:47:00.0000000Z",
				"2024-02-04T10:48:00.0000000Z",
				"2024-02-04T10:49:00.0000000Z",
				"2024-02-04T10:50:00.0000000Z",
				"2024-02-04T10:51:00.0000000Z",
				"2024-02-04T10:52:00.0000000Z",
				"2024-02-04T10:53:00.0000000Z",
				"2024-02-04T10:54:00.0000000Z",
				"2024-02-04T10:55:00.0000000Z",
				"2024-02-04T10:56:00.0000000Z",
				"2024-02-04T10:57:00.0000000Z",
				"2024-02-04T10:58:00.0000000Z",
				"2024-02-04T10:59:00.0000000Z",
				"2024-02-04T11:00:00.0000000Z",
				"2024-02-04T11:01:00.0000000Z",
				"2024-02-04T11:02:00.0000000Z",
				"2024-02-04T11:03:00.0000000Z",
				"2024-02-04T11:04:00.0000000Z",
				"2024-02-04T11:05:00.0000000Z",
				"2024-02-04T11:06:00.0000000Z",
				"2024-02-04T11:07:00.0000000Z",
				"2024-02-04T11:08:00.0000000Z",
				"2024-02-04T11:09:00.0000000Z",
				"2024-02-04T11:10:00.0000000Z",
				"2024-02-04T11:11:00.0000000Z",
				"2024-02-04T11:12:00.0000000Z",
				"2024-02-04T11:13:00.0000000Z",
				"2024-02-04T11:14:00.0000000Z",
				"2024-02-04T11:15:00.0000000Z",
				"2024-02-04T11:16:00.0000000Z",
				"2024-02-04T11:17:00.0000000Z",
				"2024-02-04T11:18:00.0000000Z",
				"2024-02-04T11:19:00.0000000Z",
				"2024-02-04T11:20:00.0000000Z",
				"2024-02-04T11:21:00.0000000Z",
				"2024-02-04T11:22:00.0000000Z",
				"2024-02-04T11:23:00.0000000Z",
				"2024-02-04T11:24:00.0000000Z",
				"2024-02-04T11:25:00.0000000Z",
				"2024-02-04T11:26:00.0000000Z",
				"2024-02-04T11:27:00.0000000Z",
				"2024-02-04T11:28:00.0000000Z",
				"2024-02-04T11:29:00.0000000Z",
				"2024-02-04T11:30:00.0000000Z",
				"2024-02-04T11:31:00.0000000Z",
				"2024-02-04T11:32:00.0000000Z",
				"2024-02-04T11:33:00.0000000Z",
				"2024-02-04T11:34:00.0000000Z",
				"2024-02-04T11:35:00.0000000Z",
				"2024-02-04T11:36:00.0000000Z",
				"2024-02-04T11:37:00.0000000Z"
			],
			"datasets": [
				{
					"label": "Total",
					"backgroundColor": "rgba(102, 153, 255, 0.1)",
					"borderColor": "rgb(102, 153, 255)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						4,
						6,
						13,
						9,
						27,
						9,
						11,
						15,
						9,
						10,
						5,
						9,
						5,
						17,
						6,
						9,
						61,
						23,
						9,
						21,
						8,
						20,
						5,
						7,
						35,
						26,
						33,
						20,
						7,
						12,
						4,
						14,
						3,
						19,
						37,
						10,
						18,
						12,
						7,
						30,
						47,
						16,
						10,
						3,
						12,
						11,
						37,
						3,
						18,
						22,
						16,
						6,
						15,
						5,
						41,
						13,
						7,
						9,
						17,
						12
					]
				},
				{
					"label": "No Error",
					"backgroundColor": "rgba(92, 184, 92, 0.1)",
					"borderColor": "rgb(92, 184, 92)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						4,
						6,
						11,
						9,
						22,
						6,
						11,
						13,
						9,
						7,
						5,
						7,
						4,
						13,
						5,
						7,
						59,
						22,
						8,
						21,
						8,
						19,
						5,
						7,
						31,
						25,
						24,
						16,
						6,
						12,
						4,
						12,
						3,
						19,
						36,
						8,
						18,
						12,
						7,
						28,
						46,
						16,
						10,
						3,
						11,
						10,
						34,
						2,
						10,
						13,
						11,
						6,
						15,
						5,
						40,
						12,
						6,
						9,
						14,
						12
					]
				},
				{
					"label": "Server Failure",
					"backgroundColor": "rgba(217, 83, 79, 0.1)",
					"borderColor": "rgb(217, 83, 79)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						1,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0
					]
				},
				{
					"label": "NX Domain",
					"backgroundColor": "rgba(120, 120, 120, 0.1)",
					"borderColor": "rgb(120, 120, 120)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						0,
						0,
						2,
						0,
						5,
						3,
						0,
						2,
						0,
						3,
						0,
						2,
						1,
						4,
						1,
						2,
						2,
						1,
						1,
						0,
						0,
						1,
						0,
						0,
						4,
						1,
						9,
						4,
						1,
						0,
						0,
						2,
						0,
						0,
						1,
						2,
						0,
						0,
						0,
						2,
						0,
						0,
						0,
						0,
						1,
						1,
						3,
						1,
						8,
						9,
						5,
						0,
						0,
						0,
						1,
						1,
						1,
						0,
						3,
						0
					]
				},
				{
					"label": "Refused",
					"backgroundColor": "rgba(91, 192, 222, 0.1)",
					"borderColor": "rgb(91, 192, 222)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0
					]
				},
				{
					"label": "Authoritative",
					"backgroundColor": "rgba(150, 150, 0, 0.1)",
					"borderColor": "rgb(150, 150, 0)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						0,
						0,
						1,
						0,
						3,
						1,
						0,
						2,
						1,
						1,
						0,
						1,
						0,
						2,
						1,
						1,
						1,
						1,
						2,
						0,
						0,
						1,
						0,
						0,
						2,
						1,
						3,
						2,
						0,
						0,
						0,
						1,
						0,
						0,
						1,
						1,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						1,
						1,
						1,
						0,
						4,
						4,
						2,
						0,
						2,
						0,
						1,
						1,
						0,
						0,
						0,
						0
					]
				},
				{
					"label": "Recursive",
					"backgroundColor": "rgba(23, 162, 184, 0.1)",
					"borderColor": "rgb(23, 162, 184)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						1,
						3,
						0,
						1,
						14,
						2,
						8,
						4,
						1,
						3,
						2,
						3,
						1,
						3,
						3,
						3,
						36,
						8,
						2,
						14,
						4,
						6,
						1,
						1,
						26,
						17,
						11,
						10,
						2,
						4,
						0,
						8,
						1,
						7,
						18,
						0,
						3,
						0,
						2,
						10,
						6,
						1,
						3,
						1,
						5,
						4,
						20,
						0,
						5,
						7,
						0,
						3,
						7,
						0,
						21,
						7,
						1,
						3,
						6,
						5
					]
				},
				{
					"label": "Cached",
					"backgroundColor": "rgba(111, 84, 153, 0.1)",
					"borderColor": "rgb(111, 84, 153)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						3,
						3,
						11,
						8,
						8,
						4,
						3,
						8,
						7,
						4,
						3,
						4,
						3,
						10,
						2,
						4,
						23,
						14,
						5,
						7,
						4,
						13,
						4,
						6,
						5,
						8,
						13,
						6,
						4,
						8,
						4,
						4,
						2,
						12,
						18,
						8,
						15,
						12,
						5,
						18,
						41,
						15,
						7,
						2,
						6,
						6,
						14,
						2,
						5,
						6,
						10,
						3,
						6,
						5,
						19,
						5,
						5,
						6,
						8,
						7
					]
				},
				{
					"label": "Blocked",
					"backgroundColor": "rgba(255, 165, 0, 0.1)",
					"borderColor": "rgb(255, 165, 0)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						0,
						0,
						1,
						0,
						2,
						2,
						0,
						1,
						0,
						2,
						0,
						1,
						1,
						2,
						0,
						1,
						1,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						2,
						0,
						6,
						2,
						1,
						0,
						0,
						1,
						0,
						0,
						0,
						1,
						0,
						0,
						0,
						2,
						0,
						0,
						0,
						0,
						0,
						0,
						2,
						1,
						4,
						5,
						4,
						0,
						0,
						0,
						0,
						0,
						1,
						0,
						3,
						0
					]
				},
				{
					"label": "Dropped",
					"backgroundColor": "rgba(30, 30, 30, 0.1)",
					"borderColor": "rgb(30, 30, 30)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0
					]
				},
				{
					"label": "Clients",
					"backgroundColor": "rgba(51, 122, 183, 0.1)",
					"borderColor": "rgb(51, 122, 183)",
					"borderWidth": 2,
					"fill": true,
					"data": [
						3,
						4,
						3,
						2,
						3,
						4,
						2,
						3,
						3,
						2,
						2,
						3,
						3,
						3,
						2,
						4,
						3,
						2,
						2,
						2,
						2,
						2,
						2,
						2,
						3,
						2,
						3,
						3,
						2,
						2,
						2,
						3,
						2,
						2,
						3,
						3,
						1,
						3,
						3,
						3,
						3,
						3,
						3,
						2,
						3,
						3,
						4,
						2,
						3,
						4,
						4,
						2,
						4,
						3,
						3,
						3,
						3,
						2,
						2,
						3
					]
				}
			]
		},
		"queryResponseChartData": {
			"labels": [
				"Authoritative",
				"Recursive",
				"Cached",
				"Blocked",
				"Dropped"
			],
			"datasets": [
				{
					"data": [
						47,
						348,
						481,
						49,
						0
					],
					"backgroundColor": [
						"rgba(150, 150, 0, 0.5)",
						"rgba(23, 162, 184, 0.5)",
						"rgba(111, 84, 153, 0.5)",
						"rgba(255, 165, 0, 0.5)",
						"rgba(7, 7, 7, 0.5)"
					]
				}
			]
		},
		"queryTypeChartData": {
			"labels": [
				"A",
				"HTTPS",
				"AAAA",
				"SOA",
				"SRV"
			],
			"datasets": [
				{
					"data": [
						683,
						196,
						42,
						2,
						2
					],
					"backgroundColor": [
						"rgba(102, 153, 255, 0.5)",
						"rgba(92, 184, 92, 0.5)",
						"rgba(7, 7, 7, 0.5)",
						"rgba(91, 192, 222, 0.5)",
						"rgba(150, 150, 0, 0.5)",
						"rgba(23, 162, 184, 0.5)",
						"rgba(111, 84, 153, 0.5)",
						"rgba(255, 165, 0, 0.5)",
						"rgba(51, 122, 183, 0.5)",
						"rgba(150, 150, 150, 0.5)"
					]
				}
			]
		},
		"protocolTypeChartData": {
			"labels": [
				"Udp"
			],
			"datasets": [
				{
					"data": [
						925
					],
					"backgroundColor": [
						"rgba(111, 84, 153, 0.5)",
						"rgba(150, 150, 0, 0.5)",
						"rgba(23, 162, 184, 0.5)",
						"rgba(255, 165, 0, 0.5)",
						"rgba(91, 192, 222, 0.5)"
					]
				}
			]
		},
		"topClients": [
			{
				"name": "192.168.10.5",
				"domain": "server1.home",
				"hits": 463,
				"rateLimited": false
			},
			{
				"name": "192.168.10.12",
				"domain": "vostro1.home",
				"hits": 236,
				"rateLimited": false
			},
			{
				"name": "192.168.10.13",
				"hits": 165,
				"rateLimited": false
			},
			{
				"name": "192.168.10.11",
				"domain": "shreyas-zare.home",
				"hits": 53,
				"rateLimited": false
			},
			{
				"name": "192.168.10.15",
				"domain": "android-9c3d70b130d99b94.home",
				"hits": 6,
				"rateLimited": false
			},
			{
				"name": "192.168.10.2",
				"domain": "pi1.home",
				"hits": 2,
				"rateLimited": false
			}
		],
		"topDomains": [
			{
				"name": "hses7-vod-cf-ace.cdn.hotstar.com",
				"hits": 114
			},
			{
				"name": "bifrost-api.hotstar.com",
				"hits": 61
			},
			{
				"name": "edge.microsoft.com",
				"hits": 52
			},
			{
				"name": "www.google.com",
				"hits": 34
			},
			{
				"name": "www.hotstar.com",
				"hits": 24
			},
			{
				"name": "safebrowsing.googleapis.com",
				"hits": 15
			},
			{
				"name": "www.bing.com",
				"hits": 14
			},
			{
				"name": "go.microsoft.com",
				"hits": 14
			},
			{
				"name": "graph.facebook.com",
				"hits": 13
			},
			{
				"name": "substrate.office.com",
				"hits": 11
			}
		],
		"topBlockedDomains": [
			{
				"name": "mobile.pipe.aria.microsoft.com",
				"hits": 10
			},
			{
				"name": "in.api.glance.inmobi.com",
				"hits": 9
			},
			{
				"name": "in.analytics.glance.inmobi.com",
				"hits": 6
			},
			{
				"name": "app-measurement.com",
				"hits": 4
			},
			{
				"name": "googleads.g.doubleclick.net",
				"hits": 4
			},
			{
				"name": "analytics.swiggy.com",
				"hits": 2
			},
			{
				"name": "firebase-settings.crashlytics.com",
				"hits": 2
			},
			{
				"name": "cdn.cookielaw.org",
				"hits": 2
			},
			{
				"name": "m.urbancompany.com",
				"hits": 1
			},
			{
				"name": "beacons.gvt2.com",
				"hits": 1
			}
		]
	},
	"status": "ok"
}
```

### Get Top Stats

Returns the top stats data for specified stats type.

URL:\
`http://localhost:5380/api/dashboard/stats/getTop?token=x&type=LastHour&statsType=TopClients&limit=1000`

OBSOLETE PATH:\
`/api/getTopStats`

PERMISSIONS:\
Dashboard: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node`: The node domain name for which the stats data is needed. When unspecified, the current node is used. Set node name as `cluster` to get aggregate stats for the entire cluster. This parameter can be used only when Clustering is initialized.
- `type` (optional): The duration type for which valid values are: [`LastHour`, `LastDay`, `LastWeek`, `LastMonth`, `LastYear`, `custom`]. Default value is `LastHour`.
- `start` (optional): The start date in ISO 8601 format. Applies only to `custom` type.
- `end` (optional): The end date in ISO 8601 format. Applies only to `custom` type.
- `statsType`: The stats type for which valid values are : [`TopClients`, `TopDomains`, `TopBlockedDomains`]
- `limit` (optional): The limit of records to return. Default value is `1000`.
- `noReverseLookup` (optional): Set to `true` to disable reverse lookup for Top Clients list. This option is only applicable with `TopClients` stats type.
- `onlyRateLimitedClients` (optional): Set to `true` to list only clients which are being rate limited in the Top Clients list. This option is only applicable with `TopClients` stats type.

RESPONSE:
The response json will include the object with definition same in the `getStats` response depending on the `statsType`. For example below is the response for `TopClients`:
```
{
	"response": {
		"topClients": [
			{
				"name": "192.168.10.5",
				"domain": "server1.local",
				"hits": 236,
				"rateLimited": false
			},
			{
				"name": "192.168.10.4",
				"domain": "nas1.local",
				"hits": 16,
				"rateLimited": false
			},
			{
				"name": "192.168.10.6",
				"domain": "server2.local",
				"hits": 14,
				"rateLimited": false
			},
			{
				"name": "192.168.10.3",
				"domain": "nas2.local",
				"hits": 12,
				"rateLimited": false
			},
			{
				"name": "217.31.193.175",
				"domain": "condor175.knot-resolver.cz",
				"hits": 10,
				"rateLimited": false
			},
			{
				"name": "162.158.180.45",
				"hits": 9,
				"rateLimited": false
			},
			{
				"name": "217.31.193.163",
				"domain": "gondor-resolver.labs.nic.cz",
				"hits": 9,
				"rateLimited": false
			},
			{
				"name": "210.245.24.68",
				"hits": 8,
				"rateLimited": false
			},
			{
				"name": "101.91.16.140",
				"hits": 8,
				"rateLimited": false
			}
		],
	},
	"status": "ok"
}
```

### Delete All Stats

Permanently delete all hourly and daily stats files from the disk and clears all stats stored in memory. This call will clear all stats from the Dashboard.

URL:\
`http://localhost:5380/api/dashboard/stats/deleteAll?token=x`

OBSOLETE PATH:\
`/api/deleteAllStats`

PERMISSIONS:\
Dashboard: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node`: The node domain name for which the stats data needs to be deleted. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

## Authoritative Zone API Calls

These API calls allow managing all hosted zones on the DNS server.

### List Zones

List all authoritative zones hosted on this DNS server. The list contains only the zones that the user has View permissions for. These API calls requires permission for both the Zones section as well as the individual permission for each zone.

URL:\
`http://localhost:5380/api/zones/list?token=x&pageNumber=1&zonesPerPage=10`

OBSOLETE PATH:\
`/api/zone/list`\
`/api/listZones`

PERMISSIONS:\
Zones: View\
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `pageNumber` (optional): When this parameter is specified, the API will return paginated results based on the page number and zones per pages options. When not specified, the API will return a list of all zones.
- `zonesPerPage` (optional): The number of zones per page to be returned. This option is only used when `pageNumber` options is specified. The default value is `10` when not specified.

RESPONSE:
```
{
	"response": {
		"pageNumber": 1,
		"totalPages": 2,
		"totalZones": 12,
		"zones": [
			{
				"name": "",
				"type": "Secondary",
				"dnssecStatus": "SignedWithNSEC",
				"soaSerial": 1,
				"expiry": "2022-02-26T07:57:08.1842183Z",
				"isExpired": false,
				"syncFailed": false,
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "0.in-addr.arpa",
				"type": "Primary",
				"internal": true,
				"dnssecStatus": "Unsigned",
				"soaSerial": 1,
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
				"type": "Primary",
				"internal": true,
				"dnssecStatus": "Unsigned",
				"soaSerial": 1,
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "127.in-addr.arpa",
				"type": "Primary",
				"internal": true,
				"dnssecStatus": "Unsigned",
				"soaSerial": 1,
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "255.in-addr.arpa",
				"type": "Primary",
				"internal": true,
				"dnssecStatus": "Unsigned",
				"soaSerial": 1,
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "example.com",
				"type": "Primary",
				"internal": false,
				"dnssecStatus": "SignedWithNSEC",
				"soaSerial": 1,
				"notifyFailed": false,
				"notifyFailedFor": [],
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "localhost",
				"type": "Primary",
				"internal": true,
				"dnssecStatus": "Unsigned",
				"soaSerial": 1,
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "test0.com",
				"type": "Primary",
				"internal": false,
				"dnssecStatus": "Unsigned",
				"soaSerial": 1,
				"notifyFailed": false,
				"notifyFailedFor": [],
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "test1.com",
				"type": "Primary",
				"internal": false,
				"dnssecStatus": "Unsigned",
				"soaSerial": 1,
				"notifyFailed": false,
				"notifyFailedFor": [],
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			},
			{
				"name": "test2.com",
				"type": "Primary",
				"internal": false,
				"dnssecStatus": "Unsigned",
				"soaSerial": 1,
				"notifyFailed": false,
				"notifyFailedFor": [],
				"lastModified": "2022-02-26T07:57:08.1842183Z",
				"disabled": false
			}
		]
	},
	"status": "ok"
}
```

### List Catalog Zones

Returns a list of Catalog zone names.

URL:\
`http://localhost:5380/api/zones/catalogs/list?token=x`

PERMISSIONS:\
Zones: View\
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {
		"catalogZoneNames": [
			"catalog1"
		]
	},
	"status": "ok"
}
```

### Create Zone

Creates a new authoritative zone.

URL:\
`http://localhost:5380/api/zones/create?token=x&zone=example.com&type=Primary`

OBSOLETE PATH:\
`/api/zone/create`\
`/api/createZone`

PERMISSIONS:\
Zones: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name for creating the new zone. The value can be valid domain name, an IP address, or an network address in CIDR format. When value is IP address or network address, a reverse zone is created.
- `type`: The type of zone to be created. Valid values are [`Primary`, `Secondary`, `Stub`, `Forwarder`, `SecondaryForwarder`, `Catalog`, `SecondaryCatalog`].
- `catalog` (optional): The name of the catalog zone to become its member zone. This option is valid only for `Primary`, `Stub`, and `Forwarder` zones.
- `useSoaSerialDateScheme` (optional): Set value to `true` to enable using date scheme for SOA serial. This optional parameter is used only with `Primary`, `Forwarder`, and `Catalog` zones. Default value is `false`.
- `primaryNameServerAddresses` (optional): List of comma separated IP addresses or domain names of the primary name server. This optional parameter is used only with `Secondary`, `SecondaryForwarder`, `SecondaryCatalog`, and `Stub` zones. If this parameter is not used, the DNS server will try to recursively resolve the primary name server addresses automatically for `Secondary` and `Stub` zones. This option is required for `SecondaryForwarder` and `SecondaryCatalog` zones.
- `zoneTransferProtocol` (optional): The zone transfer protocol to be used by `Secondary`, `SecondaryForwarder`, and `SecondaryCatalog` zones. Valid values are [`Tcp`, `Tls`, `Quic`].
- `tsigKeyName` (optional): The TSIG key name to be used by `Secondary`, `SecondaryForwarder`, and `SecondaryCatalog` zones.
- `validateZone` (optional): Set value as `true` to enable ZONEMD validation. When enabled, the `Secondary` zone will be validated using the ZONEMD record after every zone transfer. The zone will get disabled if the validation fails. The zone must be DNSSEC signed for the validation to work. This option is only valid for `Secondary` zones.
- `initializeForwarder` (optional): Set value as `true` to initialize the Conditional Forwarder zone with an FWD record or set it to `false` to create an empty `Forwarder` zone. Default value is `true`.
- `protocol` (optional): The DNS transport protocol to be used by the Conditional Forwarder zone. This optional parameter is used with Conditional Forwarder zones. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. Default `Udp` protocol is used when this parameter is missing. The `initializeForwarder` parameter must be set to `true` to use this option.
- `forwarder` (optional): The address of the DNS server to be used as a forwarder. This optional parameter is required to be used with Conditional Forwarder zones. A special value `this-server` can be used as a forwarder which when used will forward all the requests internally to this DNS server such that you can override the zone with records and rest of the zone gets resolved via This Server. The `initializeForwarder` parameter must be set to `true` to use this option.
- `dnssecValidation` (optional): Set this boolean value to indicate if DNSSEC validation must be done. This optional parameter is required to be used with Conditional Forwarder zones. The `initializeForwarder` parameter must be set to `true` to use this option.
- `proxyType` (optional): The type of proxy that must be used for conditional forwarding. This optional parameter is required to be used with Conditional Forwarder zones. Valid values are [`NoProxy`, `DefaultProxy`, `Http`, `Socks5`]. Default value `DefaultProxy` is used when this parameter is missing. The `initializeForwarder` parameter must be set to `true` to use this option.
- `proxyAddress` (optional): The proxy server address to use when `proxyType` is configured. This optional parameter is required to be used with Conditional Forwarder zones. The `initializeForwarder` parameter must be set to `true` to use this option.
- `proxyPort` (optional): The proxy server port to use when `proxyType` is configured. This optional parameter is required to be used with Conditional Forwarder zones. The `initializeForwarder` parameter must be set to `true` to use this option.
- `proxyUsername` (optional): The proxy server username to use when `proxyType` is configured. This optional parameter is required to be used with Conditional Forwarder zones. The `initializeForwarder` parameter must be set to `true` to use this option.
- `proxyPassword` (optional): The proxy server password to use when `proxyType` is configured. This optional parameter is required to be used with Conditional Forwarder zones. The `initializeForwarder` parameter must be set to `true` to use this option.

REQUEST: To import a zone file while creating a `Primary` or `Forwarder` zone, use POST request with multi-part form data containing the zone file data.

RESPONSE:
```
{
	"response": {
		"domain": "example.com"
	},
	"status": "ok"
}
```

WHERE:
- `domain`: Will contain the zone that was created. This is specifically useful to know the reverse zone that was created.

### Import Zone 

Allows importing a complete zone file or a set of DNS resource records in standard RFC 1035 zone file format.

URL:\
`http://localhost:5380/api/zones/import?token=x&zone=example.com&overwrite=true&overwriteSoaSerial=false`

PERMISSIONS:\
Zones: Modify
Zone: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to import.
- `overwrite` (optional): Set to `true` to allow overwriting existing resource record set for the records being imported.
- `overwriteSoaSerial` (optional): Set it to `true` to overwrite existing SOA record serial with the imported SOA record serial. Warning! Overwrite SOA serial option when used to set a lower SOA serial value than the current SOA serial will cause secondary zones to fail to sync.

REQUEST: This is a POST request call where the request must use `text/plain` content type with request body containing the zone file data OR the request must be multi-part form data with the zone file data.

RESPONSE:
```
{
	"status": "ok"
}
```

### Export Zone

Exports the complete zone in standard RFC 1035 zone file format.

URL:\
`http://localhost:5380/api/zones/export?token=x&zone=example.com`

PERMISSIONS:\
Zones: View
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to export.

RESPONSE: Response is a downloadable text file with `Content-Type: text/plain` and `Content-Disposition: attachment`.

### Clone Zone

Clones an existing zone with all the records to create a new zone.

URL:\
`http://localhost:5380/api/zones/clone?token=x&zone=example.com&sourceZone=template.com`

PERMISSIONS:\
Zones: Modify
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to be created.
- `sourceZone`: The domain name of the zone to be cloned.

RESPONSE:
```
{
	"status": "ok"
}
```

### Convert Zone Type

Converts zone from one type to another.

URL:\
`http://localhost:5380/api/zones/convert?token=x&zone=example.com&type=Primary`

PERMISSIONS:\
Zones: Delete
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to be converted.
- `type`: The zone type to convert the current zone to.

RESPONSE:
```
{
	"status": "ok"
}
```

### Enable Zone

Enables an authoritative zone.

URL:\
`http://localhost:5380/api/zones/enable?token=x&zone=example.com`

OBSOLETE PATH:\
`/api/zone/enable`\
`/api/enableZone`

PERMISSIONS:\
Zones: Modify\
Zone: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to be enabled.

RESPONSE:
```
{
	"status": "ok"
}
```

### Disable Zone

Disables an authoritative zone. This will prevent the DNS server from responding for queries to this zone.

URL:\
`http://localhost:5380/api/zones/disable?token=x&zone=example.com`

OBSOLETE PATH:\
`/api/zone/disable`\
`/api/disableZone`

PERMISSIONS:\
Zones: Modify\
Zone: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to be disabled.

RESPONSE:
```
{
	"status": "ok"
}
```

### Delete Zone

Deletes an authoritative zone.

URL:\
`http://localhost:5380/api/zones/delete?token=x&zone=example.com`

OBSOLETE PATH:\
`/api/zone/delete`\
`/api/deleteZone`

PERMISSIONS:\
Zones: Delete\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to be deleted.

RESPONSE:
```
{
	"status": "ok"
}
```

### Resync Zone

Allows resyncing a Secondary or Stub zone. This process will re-fetch all the records from the primary name server for the zone.

URL:\
`http://localhost:5380/api/zones/resync?token=x&zone=example.com`

OBSOLETE PATH:\
`/api/zone/resync`

PERMISSIONS:\
Zones: Modify\
Zone: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to resync.

RESPONSE:
```
{
	"status": "ok"
}
```

### Get Zone Options

Gets the zone specific options.

URL:\
`http://localhost:5380/api/zones/options/get?token=x&zone=example.com&includeAvailableTsigKeyNames=true`

OBSOLETE PATH:\
`/api/zone/options`

PERMISSIONS:\
Zones: Modify\
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to get options.
- `includeAvailableCatalogZoneNames`: Set to `true` to include list of available Catalog zone names on the DNS server.
- `includeAvailableTsigKeyNames`: Set to `true` to include list of available TSIG key names on the DNS server.

RESPONSE:
```
{
	"response": {
		"name": "example.com",
		"type": "Primary",
		"internal": false,
		"dnssecStatus": "Unsigned",
		"notifyFailed": true,
		"notifyFailedFor": [
			"192.168.10.5"
		],
		"disabled": false,
		"catalog": "catalog1",
		"overrideCatalogQueryAccess": false,
		"overrideCatalogZoneTransfer": false,
		"overrideCatalogNotify": false,
		"queryAccess": "Allow",
		"queryAccessNetworkACL": [],
		"zoneTransfer": "AllowOnlyZoneNameServers",
		"zoneTransferNetworkACL": [],
		"zoneTransferTsigKeyNames": [
			"key.example.com"
		],
		"notify": "ZoneNameServers",
		"notifyNameServers": [],
		"update": "UseSpecifiedNetworkACL",
		"updateNetworkACL": [
			"192.168.180.0/24"
		],
		"updateSecurityPolicies": [
			{
				"tsigKeyName": "key.example.com",
				"domain": "example.com",
				"allowedTypes": [
					"A",
					"AAAA"
				]
			},
			{
				"tsigKeyName": "key.example.com",
				"domain": "*.example.com",
				"allowedTypes": [
					"ANY"
				]
			}
		],
		"availableCatalogZoneNames": [
			"catalog1"
		],
		"availableTsigKeyNames": [
			"key.example.com",
			"catalog"
		]
	},
	"status": "ok"
}
```

### Set Zone Options

Sets the zone specific options.

URL:\
`http://localhost:5380/api/zones/options/set?token=x&zone=example.com&disabled=false&zoneTransfer=Allow&zoneTransferNameServers=&notify=ZoneNameServers&notifyNameServers=`

OBSOLETE PATH:\
`/api/zone/options`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to set options.
- `disabled` (optional): Sets if the zone is enabled or disabled.
- `catalog` (optional): Set a Catalog zone name to register as its member zone. This option is valid only for `Primary`, `Stub`, and `Forwarder` zones.
- `overrideCatalogQueryAccess` (optional): Set to `true` to override Query Access option in the Catalog zone. This option is valid only for `Primary`, `Stub`, and `Forwarder` zones.
- `overrideCatalogZoneTransfer` (optional): Set to `true` to override Zone Transfer option in the Catalog zone. This option is valid only for `Primary`, and `Forwarder` zones.
- `overrideCatalogNotify` (optional): Set to `true` to override Notify option in the Catalog zone.  This option is valid only for `Primary`, and `Forwarder` zones.
- `primaryNameServerAddresses` (optional): List of comma separated IP addresses or domain names of the primary name server. This optional parameter is used only with `Secondary`, `SecondaryForwarder`, `SecondaryCatalog`, and `Stub` zones. If this parameter is not used, the DNS server will try to recursively resolve the primary name server addresses automatically for `Secondary` and `Stub` zones. This option is required for `SecondaryForwarder` and `SecondaryCatalog` zones.
- `primaryZoneTransferProtocol `(optional): The zone transfer protocol to be used by `Secondary`, `SecondaryForwarder`, and `SecondaryCatalog` zones. Valid values are [`Tcp`, `Tls`, `Quic`].
- `primaryZoneTransferTsigKeyName` (optional): The TSIG key name to be used by `Secondary`, `SecondaryForwarder`, and `SecondaryCatalog` zones for zone transfer.
- `validateZone`: (optional): Set value as `true` to enable ZONEMD validation. When enabled, the `Secondary` zone will be validated using the ZONEMD record after every zone transfer. The zone will get disabled if the validation fails. The zone must be DNSSEC signed for the validation to work. This option is only valid for `Secondary` zones.
- `queryAccess` (optional): Valid options are [`Deny`, `Allow`, `AllowOnlyPrivateNetworks`, `AllowOnlyZoneNameServers`, `UseSpecifiedNetworkACL`, `AllowZoneNameServersAndUseSpecifiedNetworkACL`].
- `queryAccessNetworkACL` (optional): A comma separated Access Control List (ACL) of Network Access Control (NAC) entry. NAC is an IP address or network address to allow. Add `!` at the start of the NAC to deny access. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all except loopback. Set this parameter to `false` to remove existing values. This option is valid for all zones except `SecondaryCatalog` zone and only when `queryAccess` is set to `UseSpecifiedNetworkACL` or `AllowZoneNameServersAndUseSpecifiedNetworkACL`.
- `zoneTransfer` (optional): Sets if the zone allows zone transfer. Valid options are [`Deny`, `Allow`, `AllowOnlyZoneNameServers`, `UseSpecifiedNetworkACL`, `AllowZoneNameServersAndUseSpecifiedNetworkACL`]. This option is valid only for Primary and Secondary zones.
- `zoneTransferNetworkACL` (optional): A comma separated Access Control List (ACL) of Network Access Control (NAC) entry. NAC is an IP address or network address to allow. Add `!` at the start of the NAC to deny access. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all. Set this parameter to `false` to remove existing values. This option is valid only for `Primary`, `Secondary`, `Forwarder`, and `Catalog` zones and only when `zoneTransfer` is set to `UseSpecifiedNetworkACL` or `AllowZoneNameServersAndUseSpecifiedNetworkACL`.
- `zoneTransferTsigKeyNames` (optional): A list of comma separated TSIG keys names that are authorized to perform a zone transfer. Set this option to `false` to clear all key names. This option is valid only for `Primary`, `Secondary`, `Forwarder`, and `Catalog` zones.
- `notify` (optional): Sets if the DNS server should notify other DNS servers for zone updates. Valid options for `Primary` and `Secondary` zones are [`None`, `ZoneNameServers`, `SpecifiedNameServers`, `BothZoneAndSpecifiedNameServers`, `SeparateNameServersForCatalogAndMemberZones`]. Valid options for `Forwarder` and `Catalog` zones are [`None`, `SpecifiedNameServers`]. The `SeparateNameServersForCatalogAndMemberZones` option is valid only for `Catalog` zones. This option is valid only for `Primary`, `Secondary`, `Forwarder`, and `Catalog` zones.
- `notifyNameServers` (optional): A list of comma separated IP addresses which should be notified by the DNS server for zone updates. This list is used only when `notify` option is set to `SpecifiedNameServers` or `BothZoneAndSpecifiedNameServers`. This option is valid only for `Primary`, `Secondary`, `Forwarder`, and `Catalog` zones.
- `notifySecondaryCatalogsNameServers` (optional): A list of comma separated IP addresses which should be notified by the DNS server only for catalog zone updates. This list is used only when `notify` option is set to `SeparateNameServersForCatalogAndMemberZones`. This option is valid only for `Catalog` zones.
- `update` (optional): Sets if the DNS server should allow dynamic updates (RFC 2136). This option is valid only for `Primary`, `Secondary`, and `Forwarder` zones. Valid options for `Primary` zones are [`Deny`, `Allow`, `AllowOnlyZoneNameServers`, `UseSpecifiedNetworkACL`, `AllowZoneNameServersAndUseSpecifiedNetworkACL`]. Valid options for `Secondary` and `Forwarder` zones are [`Deny`, `Allow`, `UseSpecifiedNetworkACL`].
- `updateNetworkACL` (optional): A comma separated Access Control List (ACL) of Network Access Control (NAC) entry. NAC is an IP address or network address to allow. Add `!` at the start of the NAC to deny access. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all. Set this parameter to `false` to remove existing values. This option is valid only for `Primary`, `Secondary`, and `Forwarder` zones and only when `update` is set to `UseSpecifiedNetworkACL` or `AllowZoneNameServersAndUseSpecifiedNetworkACL`.
- `updateSecurityPolicies` (optional): A pipe `|` separated (used as both row and column separator) table data of security policies with each row containing the TSIG keys name, domain name and record types (comma separated) that are allowed. Use wildcard domain name to specify all sub domain names. Set this option to `false` to clear all security policies and stop TSIG authentication. This option is valid only for `Primary` and `Forwarder` zones.

RESPONSE:
```
{
	"status": "ok"
}
```

### Get Zone Permissions

Gets the zone specific permissions.

URL:\
`http://localhost:5380/api/zones/permissions/get?token=x&zone=example.com&includeUsersAndGroups=true`

PERMISSIONS:\
Zones: Modify\
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to get the permissions for.
- `includeUsersAndGroups`: Set to true to get a list of users and groups in the response.

RESPONSE:
```
{
	"response": {
		"section": "Zones",
		"subItem": "example.com",
		"userPermissions": [
			{
				"username": "admin",
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		],
		"groupPermissions": [
			{
				"name": "Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			{
				"name": "DNS Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		],
		"users": [
			"admin",
			"shreyas"
		],
		"groups": [
			"Administrators",
			"DHCP Administrators",
			"DNS Administrators",
			"Everyone"
		]
	},
	"status": "ok"
}
```

### Set Zone Permissions

Sets the zone specific permissions.

URL:\
`http://localhost:5380/api/zones/permissions/set?token=x&zone=example.com&userPermissions=admin|true|true|true&groupPermissions=Administrators|true|true|true|DNS%20Administrators|true|true|true`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The domain name of the zone to get the permissions for.
- `userPermissions` (optional): A pipe `|` separated table data with each row containing username and boolean values for the view, modify and delete permissions. For example: user1|true|true|true|user2|true|false|false
- `groupPermissions` (optional): A pipe `|` separated table data with each row containing the group name and boolean values for the view, modify and delete permissions. For example: group1|true|true|true|group2|true|true|false

RESPONSE:
```
{
	"response": {
		"section": "Zones",
		"subItem": "example.com",
		"userPermissions": [
			{
				"username": "admin",
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		],
		"groupPermissions": [
			{
				"name": "Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			{
				"name": "DNS Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			}
		]
	},
	"status": "ok"
}
```

### Sign Zone

Signs the primary zone (DNSSEC).

URL:\
`http://localhost:5380/api/zones/dnssec/sign?token=x&zone=example.com&algorithm=ECDSA&dnsKeyTtl=86400&zskRolloverDays=30&nxProof=NSEC3&iterations=0&saltLength=0&curve=P256`

OBSOLETE PATH:\
`/api/zone/dnssec/sign`

PERMISSONS:
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone to sign.
- `algorithm`: The algorithm to be used for signing. Valid values are [`RSA`, `ECDSA`, `EDDSA`].
- `pemKskPrivateKey` (optional): The user specified private key in PEM format for Key Signing Key (KSK). When this parameter is specified, the private key specified is used instead of automatically generating it.
- `pemZskPrivateKey` (optional): The user specified private key in PEM format for Zone Signing Key (ZSK). When this parameter is specified, the private key specified is used instead of automatically generating it.
- `hashAlgorithm` (optional): The hash algorithm to be used when using `RSA` algorithm. Valid values are [`MD5`, `SHA1`, `SHA256`, `SHA512`]. This optional parameter is required when using `RSA` algorithm.
- `kskKeySize` (optional): The size of the Key Signing Key (KSK) in bits to be used when using `RSA` algorithm. This optional parameter is required when using `RSA` algorithm.
- `zskKeySize` (optional): The size of the Zone Signing Key (ZSK) in bits to be used when using `RSA` algorithm. This optional parameter is required when using `RSA` algorithm.
- `curve` (optional): The name of the curve to be used when using `ECDSA` or `EDDSA` algorithm. Valid values are [`P256`, `P384`] for `ECDSA` algorithm and [`ED25519`, `ED448`] for `EDDSA` algorithm. This optional parameter is required when using `ECDSA` or `EDDSA` algorithm.
- `dnsKeyTtl` (optional): The TTL value to be used for DNSKEY records. Default value is `86400` when not specified.
- `zskRolloverDays` (optional): The frequency in days that the DNS server must automatically rollover the Zone Signing Keys (ZSK) in the zone. Valid range is 0-365 days where 0 disables rollover. Default value is `30` when not specified.
- `nxProof` (optional): The type of proof of non-existence that must be used for signing the zone. Valid values are [`NSEC`, `NSEC3`]. Default value is `NSEC` when not specified.
- `iterations` (optional): The number of iterations to use for hashing in NSEC3. This optional parameter is only applicable when using `NSEC3` as the `nxProof`. Default value is `0` when not specified.
- `saltLength` (optional): The length of salt in bytes to use for hashing in NSEC3. This optional parameter is only applicable when using `NSEC3` as the `nxProof`. Default value is `0` when not specified.

RESPONSE:
```
{
	"status": "ok"
}
```

### Unsign Zone

Unsigns the primary zone (DNSSEC).

URL:\
`http://localhost:5380/api/zones/dnssec/unsign?token=x&zone=example.com

OBSOLETE PATH:\
`/api/zone/dnssec/unsign`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone to unsign.

RESPONSE:
```
{
	"status": "ok"
}
```

### Get DS Info

Get the DS info for the signed primary zone to help with updating DS records at the parent zone.

URL:\
`http://localhost:5380/api/zones/dnssec/viewDS?token=x&zone=example.com

PERMISSIONS:\
Zones: View\
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the signed primary zone.

RESPONSE:
```
{
	"response": {
		"name": "example.com",
		"type": "Primary",
		"internal": false,
		"disabled": false,
		"dnssecStatus": "SignedWithNSEC",
		"dsRecords": [
			{
				"keyTag": 47972,
				"dnsKeyState": "Published",
				"dnsKeyStateReadyBy": "2023-10-29T16:20:08.8007369Z",
				"algorithm": "ECDSAP256SHA256",
				"publicKey": "TK5a8pXPMspDwuh4Z3evOfNZm9kkc8IzwZDiCgIX6imxwkbpY9FTvhoI/ttZiLWZ5hvLbvrpsbd0liqSwqNmPg==",
				"digests": [
					{
						"digestType": "SHA256",
						"digest": "D59EBB413C88576B519B2980DF50493689A4A260383D0CB2F260251D5CA2E144"
					},
					{
						"digestType": "SHA384",
						"digest": "F8235EEAB1AEBCFAD28096DF8DCF820F25C685041562AAB63E1A3E1AC89D2FC3836E97114A64EC0E057DCA234451E50C"
					}
				]
			}
		]
	},
	"status": "ok"
}
```

### Get DNSSEC Properties

Get the DNSSEC properties for the primary zone.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/get?token=x&zone=example.com`

OBSOLETE PATH:\
`/api/zone/dnssec/getProperties`

PERMISSIONS:\
Zones: Modify\
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.

RESPONSE:
```
{
	"response": {
		"name": "example.com",
		"type": "Primary",
		"internal": false,
		"disabled": false,
		"dnssecStatus": "SignedWithNSEC",
		"dnsKeyTtl": 3600,
		"dnssecPrivateKeys": [
			{
				"keyTag": 15048,
				"keyType": "KeySigningKey",
				"algorithm": "ECDSAP256SHA256",
				"state": "Published",
				"stateChangedOn": "2022-12-18T14:39:50.0328321Z",
				"stateReadyBy": "2022-12-18T16:14:50.0328321Z",
				"isRetiring": false,
				"rolloverDays": 0
			},
			{
				"keyTag": 46152,
				"keyType": "ZoneSigningKey",
				"algorithm": "ECDSAP256SHA256",
				"state": "Active",
				"stateChangedOn": "2022-12-18T14:39:50.0661173Z",
				"isRetiring": false,
				"rolloverDays": 90
			}
		]
	},
	"status": "ok"
}
```

### Convert To NSEC

Converts a primary zone from NSEC3 to NSEC for proof of non-existence.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/convertToNSEC?token=x&zone=example.com`

OBSOLETE PATH:\
`/api/zone/dnssec/convertToNSEC`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.

RESPONSE:
```
{
	"status": "ok"
}
```

### Convert To NSEC3

Converts a primary zone from NSEC to NSEC3 for proof of non-existence.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/convertToNSEC3?token=x&zone=example.com`

OBSOLETE PATH:\
`/api/zone/dnssec/convertToNSEC3`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.

RESPONSE:
```
{
	"status": "ok"
}
```

### Update NSEC3 Parameters

Updates the iteration and salt length parameters for NSEC3.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/updateNSEC3Params?token=x&zone=example.com&iterations=0&saltLength=0`

OBSOLETE PATH:\
`/api/zone/dnssec/updateNSEC3Params`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.
- `iterations` (optional): The number of iterations to use for hashing. Default value is `0` when not specified.
- `saltLength` (optional): The length of salt in bytes to use for hashing. Default value is `0` when not specified.

RESPONSE:
```
{
	"status": "ok"
}
```

### Update DNSKEY TTL

Updates the TTL value for DNSKEY resource record set. The value can be updated only when all the DNSKEYs are in ready or active state.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/updateDnsKeyTtl?token=x&zone=example.com&ttl=86400`

OBSOLETE PATH:\
`/api/zone/dnssec/updateDnsKeyTtl`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.
- `ttl`: The TTL value for the DNSKEY resource record set.

RESPONSE:
```
{
	"status": "ok"
}
```

### Add Private Key

Adds a private key to be used for signing the zone with DNSSEC.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/addPrivateKey?token=x&zone=example.com&keyType=KeySigningKey&algorithm=ECDSA&curve=P256`

OBSOLETE PATH:\
`/api/zone/dnssec/generatePrivateKey`\
`/api/zones/dnssec/properties/generatePrivateKey`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.
- `keyType`: The type of key for which the private key is to be generated. Valid values are [`KeySigningKey`, `ZoneSigningKey`].
- `rolloverDays` (optional): The frequency in days that the DNS server must automatically rollover the private key in the zone. Valid range is 0-365 days where 0 disables rollover. Default value is 90 days for Zone Signing Key (ZSK) and 0 days for Key Signing Key (KSK).
- `algorithm`: The algorithm to be used for signing. Valid values are [`RSA`, `ECDSA`, `EDDSA`].
- `pemPrivateKey` (optional): Specifies a user generated private key in PEM format to add. When not specified a private key will be automatically generated.
- `hashAlgorithm` (optional): The hash algorithm to be used when using `RSA` algorithm. Valid values are [`MD5`, `SHA1`, `SHA256`, `SHA512`]. This optional parameter is required when using `RSA` algorithm.
- `keySize` (optional): The size of the generated private key in bits to be used when using `RSA` algorithm. This optional parameter is required when using `RSA` algorithm.
- `curve` (optional): The name of the curve to be used when using `ECDSA` or `EDDSA` algorithm. Valid values are [`P256`, `P384`] for `ECDSA` algorithm and [`ED25519`, `ED448`] for `EDDSA` algorithm. This optional parameter is required when using `ECDSA` or `EDDSA` algorithm.

RESPONSE:
```
{
	"status": "ok"
}
```

### Update Private Key

Updates the DNSSEC private key properties.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/updatePrivateKey?token=x&zone=example.com&keyTag=1234&rolloverDays=90`

OBSOLETE PATH:\
`/api/zone/dnssec/updatePrivateKey`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.
- `keyTag`: The key tag of the private key to be updated.
- `rolloverDays`: The frequency in days that the DNS server must automatically rollover the private key in the zone. Valid range is 0-365 days where 0 disables rollover. 

RESPONSE:
```
{
	"status": "ok"
}
```

### Delete Private Key

Deletes a private key that has state set as `Generated`. Private keys with any other state cannot be delete.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/deletePrivateKey?token=x&zone=example.com&keyTag=12345`

OBSOLETE PATH:\
`/api/zone/dnssec/deletePrivateKey`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.
- `keyTag`: The key tag of the private key to be deleted.

RESPONSE:
```
{
	"status": "ok"
}
```

### Publish All Private Keys

Publishes all private keys that have state set as `Generated` by adding associated DNSKEY records for them. Once published, the keys will be automatically activated. For Key Signing Keys (KSK), once the state is set to `Ready` you can then safely replace the old DS record from the parent zone with a new DS key record for the KSK associated DNSKEY record. Once the new DS record is published at the parent zone, the DNS server will automatically detect and set the KSK state to `Active`.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/publishAllPrivateKeys?token=x&zone=example.com`

OBSOLETE PATH:\
`/api/zone/dnssec/publishAllPrivateKeys`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.

RESPONSE:
```
{
	"status": "ok"
}
```

### Rollover DNSKEY

Generates and publishes a new private key for the given key that has to be rolled over. The old private key and its associated DNSKEY record will be automatically retired and removed safely once the new key is active.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/rolloverDnsKey?token=x&zone=example.com&keyTag=12345`

OBSOLETE PATH:\
`/api/zone/dnssec/rolloverDnsKey`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.
- `keyTag`: The key tag of the private key to rollover.

RESPONSE:
```
{
	"status": "ok"
}
```

### Retire DNSKEY

Retires the specified private key and its associated DNSKEY record and removes it safely. To retire an existing DNSKEY, there must be at least one active key available.

URL:\
`http://localhost:5380/api/zones/dnssec/properties/retireDnsKey?token=x&zone=example.com&keyTag=12345`

OBSOLETE PATH:\
`/api/zone/dnssec/retireDnsKey`

PERMISSIONS:\
Zones: Modify\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `zone`: The name of the primary zone.
- `keyTag`: The key tag of the private key to retire.

RESPONSE:
```
{
	"status": "ok"
}
```

### Add Record

Adds an resource record for an authoritative zone.

URL:\
`http://localhost:5380/api/zones/records/add?token=x&domain=example.com&zone=example.com`

OBSOLETE PATH:\
`/api/zone/addRecord`\
`/api/addRecord`

PERMISSIONS:\
Zones: None\
Zone: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `domain`: The domain name of the zone to add record.
- `zone` (optional): The name of the authoritative zone into which the `domain` exists. When unspecified, the closest authoritative zone will be used.
- `type`: The DNS resource record type. Supported record types are [`A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `TXT`, `SRV`, `DNAME`, `DS`, `SSHFP`, `TLSA`, `SVCB`, `HTTPS`, `URI`, `CAA`] and proprietary types [`ANAME`, `FWD`, `APP`]. Unknown record types are also supported since v11.2.
- `ttl` (optional): The DNS resource record TTL value. This is the value in seconds that the DNS resolvers can cache the record for. When not specified the default TTL value from settings will be used.
- `overwrite` (optional): This option when set to `true` will overwrite existing resource record set for the selected `type` with the new record. Default value of `false` will add the new record into existing resource record set.
- `comments` (optional): Sets comments for the added resource record.
- `expiryTtl` (optional): Set to automatically delete the record when the value in seconds elapses since the record’s last modified time.
- `ipAddress` (optional): The IP address for adding `A` or `AAAA` record. A special value of `request-ip-address` can be used to set the record with the IP address of the API HTTP request to help with dynamic DNS update applications. This option is required and used only for `A` and `AAAA` records.
- `ptr` (optional): Set this option to `true` to add a reverse PTR record for the IP address in the `A` or `AAAA` record. This option is used only for `A` and `AAAA` records.
- `createPtrZone` (optional): Set this option to `true` to create a reverse zone for PTR record. This option is used for `A` and `AAAA` records.
- `updateSvcbHints` (optional): Set this option to `true` to update any SVCB/HTTPS records in the zone that has Automatic Hints option enabled and matches its target name with the current record's domain name. This option is used for `A` and `AAAA` records.
- `nameServer` (optional): The name server domain name. This option is required for adding `NS` record.
- `glue` (optional): This is the glue address for the name server in the `NS` record. This optional parameter is used for adding `NS` record.
- `cname` (optional): The CNAME domain name. This option is required for adding `CNAME` record.
- `ptrName` (optional): The PTR domain name. This option is required for adding `PTR` record.
- `exchange` (optional): The exchange domain name. This option is required for adding `MX` record.
- `preference` (optional): This is the preference value for `MX` record type. This option is required for adding `MX` record.
- `text` (optional): The text data for `TXT` record. This option is required for adding `TXT` record.
- `splitText` (optional): Set to `true` for using new line char to split text into multiple character-strings for adding `TXT` record.
- `mailbox` (optional): Set an email address for adding `RP` record.
- `txtDomain` (optional): Set a `TXT` record's domain name for adding `RP` record.
- `priority` (optional): This parameter is required for adding the `SRV` record.
- `weight` (optional): This parameter is required for adding the `SRV` record.
- `port` (optional): This parameter is required for adding the `SRV` record.
- `target` (optional): This parameter is required for adding the `SRV` record.
- `naptrOrder` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrPreference` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrFlags` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrServices` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrRegexp` (optional): This parameter is required for adding the `NAPTR` record.
- `naptrReplacement` (optional): This parameter is required for adding the `NAPTR` record.
- `dname` (optional): The DNAME domain name. This option is required for adding `DNAME` record.
- `keyTag` (optional): This parameter is required for adding `DS` record.
- `algorithm` (optional): Valid values are [`RSAMD5`, `DSA`, `RSASHA1`, `DSA-NSEC3-SHA1`, `RSASHA1-NSEC3-SHA1`, `RSASHA256`, `RSASHA512`, `ECC-GOST`, `ECDSAP256SHA256`, `ECDSAP384SHA384`, `ED25519`, `ED448`]. This parameter is required for adding `DS` record.
- `digestType` (optional): Valid values are [`SHA1`, `SHA256`, `GOST-R-34-11-94`, `SHA384`]. This parameter is required for adding `DS` record.
- `digest` (optional): A hex string value. This parameter is required for adding `DS` record.
- `sshfpAlgorithm` (optional): Valid values are [`RSA`, `DSA`, `ECDSA`, `Ed25519`, `Ed448`]. This parameter is required for adding `SSHFP` record.
- `sshfpFingerprintType` (optional): Valid values are [`SHA1`, `SHA256`]. This parameter is required for adding `SSHFP` record.
- `sshfpFingerprint` (optional): A hex string value. This parameter is required for adding `SSHFP` record.
- `tlsaCertificateUsage` (optional): Valid values are [`PKIX-TA`, `PKIX-EE`, `DANE-TA`, `DANE-EE`]. This parameter is required for adding `TLSA` record.
- `tlsaSelector` (optional): Valid values are [`Cert`, `SPKI`]. This parameter is required for adding `TLSA` record.
- `tlsaMatchingType` (optional): Valid value are [`Full`, `SHA2-256`, `SHA2-512`]. This parameter is required for adding `TLSA` record.
- `tlsaCertificateAssociationData` (optional): A X509 certificate in PEM format or a hex string value. This parameter is required for adding `TLSA` record.
- `svcPriority` (optional): The priority value for `SVCB` or `HTTPS` record. This parameter is required for adding `SCVB` or `HTTPS` record.
- `svcTargetName` (optional): The target domain name for `SVCB` or `HTTPS` record. This parameter is required for adding `SCVB` or `HTTPS` record.
- `svcParams` (optional): The service parameters for `SVCB` or `HTTPS` record which is a pipe separated list of key and value. For example, `alpn|h2,h3|port|53443`. To clear existing values, set it to `false`. This parameter is required for adding `SCVB` or `HTTPS` record.
- `autoIpv4Hint` (optional): Set this option to `true` to enable Automatic Hints for the `ipv4hint` parameter in the `svcParams`. This option is valid only for `SVCB` and `HTTPS` records.
- `autoIpv6Hint` (optional): Set this option to `true` to enable Automatic Hints for the `ipv6hint` parameter in the `svcParams`. This option is valid only for `SVCB` and `HTTPS` records.
- `uriPriority` (optional): The priority value for adding the `URI` record.
- `uriWeight` (optional): The weight value for adding the `URI` record.
- `uri` (optional): The URI value for adding the `URI` record.
- `flags` (optional): This parameter is required for adding the `CAA` record.
- `tag` (optional): This parameter is required for adding the `CAA` record.
- `value` (optional): This parameter is required for adding the `CAA` record.
- `aname` (optional): The ANAME domain name. This option is required for adding `ANAME` record.
- `protocol` (optional): This parameter is required for adding the `FWD` record. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`].
- `forwarder` (optional): The forwarder address. A special value of `this-server` can be used to directly forward requests internally to the DNS server. This parameter is required for adding the `FWD` record.
- `forwarderPriority` (optional): Set an integer priority value for adding the `FWD` record. Forwarders with high priority (lower value) will be queried before trying for low priority forwarders. Forwarders with the same priority will be concurrently queried.
- `dnssecValidation` (optional): Set this boolean value to indicate if DNSSEC validation must be done. This optional parameter is to be used with FWD records. Default value is `false`.
- `proxyType` (optional): The type of proxy that must be used for conditional forwarding. This optional parameter is to be used with FWD records. Valid values are [`NoProxy`, `DefaultProxy`, `Http`, `Socks5`]. Default value `DefaultProxy` is used when this parameter is missing.
- `proxyAddress` (optional): The proxy server address to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyPort` (optional): The proxy server port to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyUsername` (optional): The proxy server username to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyPassword` (optional): The proxy server password to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `appName` (optional): The name of the DNS app. This parameter is required for adding the `APP` record.
- `classPath` (optional): This parameter is required for adding the `APP` record.
- `recordData` (optional): This parameter is used for adding the `APP` record as per the DNS app requirements.
- `rdata` (optional): This parameter is used for adding unknown i.e. unsupported record types. The value must be formatted as a hex string or a colon separated hex string.

RESPONSE:
```
{
	"response": {
		"zone": {
			"name": "example.com",
			"type": "Primary",
			"internal": false,
			"dnssecStatus": "SignedWithNSEC",
			"disabled": false
		},
		"addedRecord": {
			"disabled": false,
			"name": "example.com",
			"type": "A",
			"ttl": 3600,
			"rData": {
				"ipAddress": "3.3.3.3"
			},
			"dnssecStatus": "Unknown",
			"lastUsedOn": "0001-01-01T00:00:00"
		}
	},
	"status": "ok"
}
```

### Get Records

Gets all records for a given authoritative zone.

URL:\
`http://localhost:5380/api/zones/records/get?token=x&domain=example.com&zone=example.com&listZone=true`

OBSOLETE PATH:\
`/api/zone/getRecords`\
`/api/getRecords`

PERMISSIONS:\
Zones: None\
Zone: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `domain`: The domain name of the zone to get records.
- `zone` (optional): The name of the authoritative zone into which the `domain` exists. When unspecified, the closest authoritative zone will be used.
- `listZone` (optional): When set to `true` will list all records in the zone else will list records only for the given domain name. Default value is `false` when not specified.

RESPONSE:
```
{
	"response": {
		"zone": {
			"name": "example.com",
			"type": "Primary",
			"internal": false,
			"dnssecStatus": "SignedWithNSEC3",
			"disabled": false
		},
		"records": [
			{
				"disabled": false,
				"name": "example.com",
				"type": "A",
				"ttl": 3600,
				"rData": {
					"ipAddress": "1.1.1.1"
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "NS",
				"ttl": 3600,
				"rData": {
					"nameServer": "server1"
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "SOA",
				"ttl": 900,
				"rData": {
					"primaryNameServer": "server1",
					"responsiblePerson": "hostadmin.example.com",
					"serial": 35,
					"refresh": 900,
					"retry": 300,
					"expire": 604800,
					"minimum": 900
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "RRSIG",
				"ttl": 900,
				"rData": {
					"typeCovered": "NSEC3PARAM",
					"algorithm": "ECDSAP256SHA256",
					"labels": 2,
					"originalTtl": 900,
					"signatureExpiration": "2022-03-15T11:45:31Z",
					"signatureInception": "2022-03-05T10:45:31Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "vJ/fXkGKsapdvWjDhcfHsBxpZhSzMRLZv3/bEGJ4N3/K7jiM92Ik336W680SI7g+NyPCQ3gqE7ta/JEL4bht4Q=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "RRSIG",
				"ttl": 900,
				"rData": {
					"typeCovered": "SOA",
					"algorithm": "ECDSAP256SHA256",
					"labels": 2,
					"originalTtl": 900,
					"signatureExpiration": "2022-03-15T12:53:39Z",
					"signatureInception": "2022-03-05T11:53:39Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "9PQHH3ZGCuFRYkn28SoilS8y8zszgeOpCfJpIOAaE5ao+iBPCXudHacr/EpgB2wLzXpRjR+WgiYjmJH17+6bKg=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "RRSIG",
				"ttl": 3600,
				"rData": {
					"typeCovered": "A",
					"algorithm": "ECDSAP256SHA256",
					"labels": 2,
					"originalTtl": 3600,
					"signatureExpiration": "2022-03-15T11:25:35Z",
					"signatureInception": "2022-03-05T10:25:35Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "dWjn5hTWuEq57ncwGdVq+kdbMuFtuxLuZhYCcQMdsTxYkM/64RrPY6eYwfYQ7+fY1+QBSX2WudAM4dzbmL/s2A=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "RRSIG",
				"ttl": 3600,
				"rData": {
					"typeCovered": "NS",
					"algorithm": "ECDSAP256SHA256",
					"labels": 2,
					"originalTtl": 3600,
					"signatureExpiration": "2022-03-15T11:25:35Z",
					"signatureInception": "2022-03-05T10:25:35Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "Yx+leBcYNFf0gUfN6rECWrUZwCDhJbAGk1BNOJN01nPakS5meSbDApUHJZeAzfSBcPzodK3ddmEuhho1MABaZw=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "RRSIG",
				"ttl": 86400,
				"rData": {
					"typeCovered": "DNSKEY",
					"algorithm": "ECDSAP256SHA256",
					"labels": 2,
					"originalTtl": 86400,
					"signatureExpiration": "2022-03-15T12:27:09Z",
					"signatureInception": "2022-03-05T11:27:09Z",
					"keyTag": 65078,
					"signersName": "example.com",
					"signature": "KWAK7o+FjJ2/6ZvX4C1wB41yRzlmec5pR2TTeNWlY/weg0MNKCLRs3uTopSjoTih+uq3IRR7Zx0iOcy7evOitA=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "RRSIG",
				"ttl": 86400,
				"rData": {
					"typeCovered": "DNSKEY",
					"algorithm": "ECDSAP256SHA256",
					"labels": 2,
					"originalTtl": 86400,
					"signatureExpiration": "2022-03-15T12:27:09Z",
					"signatureInception": "2022-03-05T11:27:09Z",
					"keyTag": 52896,
					"signersName": "example.com",
					"signature": "oHtt1gUmDXxI5GMfS+LJ6uxKUcuUu+5EELXdhLrbk5V/yganP6sMgA4hGkzokYM22LDowjSdO5qwzCW6IDgKxg=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "DNSKEY",
				"ttl": 86400,
				"rData": {
					"flags": "SecureEntryPoint, ZoneKey",
					"protocol": 3,
					"algorithm": "ECDSAP256SHA256",
					"publicKey": "dMRyc/Pji31mF3iHNrybPzbgvtb2NKtmXhjQq433BHI= ZveDa1z00VxDnugV1x7EDvpt+42TDh8OQwp1kOrpX0E=",
					"computedKeyTag": 65078,
					"dnsKeyState": "Ready",
					"computedDigests": [
						{
							"digestType": "SHA256",
							"digest": "BBE017B17E5CB5FFFF1EC2C7815367DF80D8E7EAEE4832D3ED192159D79B1EEB"
						},
						{
							"digestType": "SHA384",
							"digest": "0B0C9F1019BD3FE62C8B71F8C80E7A833BA468A7E303ABC819C0CB9BEDE8E26BB50CB1729547BFCCE2AE22390E44CDA3"
						}
					]
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "DNSKEY",
				"ttl": 86400,
				"rData": {
					"flags": "ZoneKey",
					"protocol": 3,
					"algorithm": "ECDSAP256SHA256",
					"publicKey": "IUvzTkf4JPg+7k57cQw7n7SR6/1dH7FaKxu9Cf+kcvo= UU+uoKRWnYAFHDNF0X3U8ZYetUyDF7fcNAwEaSQnIUM=",
					"computedKeyTag": 61009,
					"dnsKeyState": "Active"
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "DNSKEY",
				"ttl": 3600,
				"rData": {
					"flags": "SecureEntryPoint, ZoneKey",
					"protocol": 3,
					"algorithm": "ECDSAP256SHA256",
					"publicKey": "KOJWFitKm58EgjO43GDnsFbnkGoqVKeLRkP8FGPAdhqA2F758Ta1mkxieEu0YN0EoX+u5bVuc5DEBFSv+U63CA==",
					"computedKeyTag": 15048,
					"dnsKeyState": "Published",
					"dnsKeyStateReadyBy": "2022-12-18T16:14:50.0328321Z",
					"computedDigests": [
						{
							"digestType": "SHA256",
							"digest": "8EAFAE3305DB57A27CA5A261525515461CB7232A34A44AD96441B88BCA9B9849"
						},
						{
							"digestType": "SHA384",
							"digest": "4A6DA59E91872B5B835FCEE5987B17151A6F10FE409B595BEEEDB28FE64315C9C268493B59A0BF72EA84BE0F20A33F96"
						}
					]
				},
				"dnssecStatus": "Unknown",
				"lastUsedOn": "0001-01-01T00:00:00"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "DNSKEY",
				"ttl": 86400,
				"rData": {
					"flags": "ZoneKey",
					"protocol": 3,
					"algorithm": "ECDSAP256SHA256",
					"publicKey": "337uQ11fdKbr6sKYq9mwwBC2xdnu0geuIkfHcIauKNI= rKk7pfVKlLfcGBOIn5hEVeod2aIRIyUiivdTPzrmpIo=",
					"computedKeyTag": 4811,
					"dnsKeyState": "Published"
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "example.com",
				"type": "NSEC3PARAM",
				"ttl": 900,
				"rData": {
					"hashAlgorithm": "SHA1",
					"flags": "None",
					"iterations": 0,
					"salt": ""
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "*.example.com",
				"type": "A",
				"ttl": 3600,
				"rData": {
					"ipAddress": "7.7.7.7"
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "*.example.com",
				"type": "RRSIG",
				"ttl": 3600,
				"rData": {
					"typeCovered": "A",
					"algorithm": "ECDSAP256SHA256",
					"labels": 2,
					"originalTtl": 3600,
					"signatureExpiration": "2022-03-15T11:25:35Z",
					"signatureInception": "2022-03-05T10:25:35Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "ZoUNNEdb8XWqHHi5o4BcUe7deRVlJZLhQtc3sjRtuJ68DNPDmQ0GfCrNTigJcomspr7CYqWcXfoSOqu6f2AyyQ=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "4F3CNT8CU22TNGEC382JJ4GDE4RB47UB.example.com",
				"type": "RRSIG",
				"ttl": 900,
				"rData": {
					"typeCovered": "NSEC3",
					"algorithm": "ECDSAP256SHA256",
					"labels": 3,
					"originalTtl": 900,
					"signatureExpiration": "2022-03-15T11:45:31Z",
					"signatureInception": "2022-03-05T10:45:31Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "piZeLYa6WpHyiJerPlXq2s+JKBjHznNALXHJCOfiQ4o/iTqWILoqYHfKB5AWrLwLmkxXcbKf63CnEMGlinRidg=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "4F3CNT8CU22TNGEC382JJ4GDE4RB47UB.example.com",
				"type": "NSEC3",
				"ttl": 900,
				"rData": {
					"hashAlgorithm": "SHA1",
					"flags": "None",
					"iterations": 0,
					"salt": "",
					"nextHashedOwnerName": "KG19N32806C832KIJDNGLQ8P9M2R5MDJ",
					"types": [
						"A"
					]
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "KG19N32806C832KIJDNGLQ8P9M2R5MDJ.example.com",
				"type": "RRSIG",
				"ttl": 900,
				"rData": {
					"typeCovered": "NSEC3",
					"algorithm": "ECDSAP256SHA256",
					"labels": 3,
					"originalTtl": 900,
					"signatureExpiration": "2022-03-15T11:45:31Z",
					"signatureInception": "2022-03-05T10:45:31Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "i/PMxc1LFA9a8jLxju7SSpoY7y8aZYkAILcCRIxE3lTundPJmzFG0U9kve04kqT7+Klmzj3OzXnCvjTA54+DZA=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "KG19N32806C832KIJDNGLQ8P9M2R5MDJ.example.com",
				"type": "NSEC3",
				"ttl": 900,
				"rData": {
					"hashAlgorithm": "SHA1",
					"flags": "None",
					"iterations": 0,
					"salt": "",
					"nextHashedOwnerName": "MIFDNDT3NFF3OD53O7TLA1HRFF95JKUK",
					"types": [
						"NS",
						"DS"
					]
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "MIFDNDT3NFF3OD53O7TLA1HRFF95JKUK.example.com",
				"type": "RRSIG",
				"ttl": 900,
				"rData": {
					"typeCovered": "NSEC3",
					"algorithm": "ECDSAP256SHA256",
					"labels": 3,
					"originalTtl": 900,
					"signatureExpiration": "2022-03-15T11:45:31Z",
					"signatureInception": "2022-03-05T10:45:31Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "mr37TDMmWJ3YLNtpYy++S9eAeHIXKajX6jB8zLscJyC1uI0OFnSTuesfhIlLDbj0SDgrzRQWsLmvMKzfq89TJA=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "MIFDNDT3NFF3OD53O7TLA1HRFF95JKUK.example.com",
				"type": "NSEC3",
				"ttl": 900,
				"rData": {
					"hashAlgorithm": "SHA1",
					"flags": "None",
					"iterations": 0,
					"salt": "",
					"nextHashedOwnerName": "ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK",
					"types": [
						"CNAME"
					]
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK.example.com",
				"type": "RRSIG",
				"ttl": 900,
				"rData": {
					"typeCovered": "NSEC3",
					"algorithm": "ECDSAP256SHA256",
					"labels": 3,
					"originalTtl": 900,
					"signatureExpiration": "2022-03-15T11:45:31Z",
					"signatureInception": "2022-03-05T10:45:31Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "GGh/KkB6C2D55xRJa0zFbZ8As3DZK9btUamryZVmyo7FaLPyltkeRZor9OExgQ6HC1SLXNGJIfCO9cM4K6P8iw=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK.example.com",
				"type": "NSEC3",
				"ttl": 900,
				"rData": {
					"hashAlgorithm": "SHA1",
					"flags": "None",
					"iterations": 0,
					"salt": "",
					"nextHashedOwnerName": "4F3CNT8CU22TNGEC382JJ4GDE4RB47UB",
					"types": [
						"A",
						"NS",
						"SOA",
						"DNSKEY",
						"NSEC3PARAM"
					]
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "sub.example.com",
				"type": "NS",
				"ttl": 3600,
				"rData": {
					"nameServer": "server1"
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "sub.example.com",
				"type": "DS",
				"ttl": 3600,
				"rData": {
					"keyTag": 46125,
					"algorithm": "ECDSAP384SHA384",
					"digestType": "SHA1",
					"digest": "5590E425472785A16DC0F853000557DB5543C39E"
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "sub.example.com",
				"type": "RRSIG",
				"ttl": 3600,
				"rData": {
					"typeCovered": "NS",
					"algorithm": "ECDSAP256SHA256",
					"labels": 3,
					"originalTtl": 3600,
					"signatureExpiration": "2022-03-15T11:25:35Z",
					"signatureInception": "2022-03-05T10:25:35Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "hFzYTL9V0/0UQZlvZpRWCOvu/2udvhswKoxpe4+quNuC6K59W7uCJLuDm/z0aFK5nW8Of4oTk2YjSBZo0nBSlg=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "sub.example.com",
				"type": "RRSIG",
				"ttl": 3600,
				"rData": {
					"typeCovered": "DS",
					"algorithm": "ECDSAP256SHA256",
					"labels": 3,
					"originalTtl": 3600,
					"signatureExpiration": "2022-03-15T12:53:39Z",
					"signatureInception": "2022-03-05T11:53:39Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "UYpUKV5Uq7DM3rltg3sPFOwYgRa2yBzT/j9U8xCh5oyXt27fIn3eemvqqe9qV4xeQaAN0QfQPkj9vmOZSAYafg=="
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "www.example.com",
				"type": "CNAME",
				"ttl": 3600,
				"rData": {
					"cname": "example.com"
				},
				"dnssecStatus": "Unknown"
			},
			{
				"disabled": false,
				"name": "www.example.com",
				"type": "RRSIG",
				"ttl": 3600,
				"rData": {
					"typeCovered": "CNAME",
					"algorithm": "ECDSAP256SHA256",
					"labels": 3,
					"originalTtl": 3600,
					"signatureExpiration": "2022-03-15T11:25:35Z",
					"signatureInception": "2022-03-05T10:25:35Z",
					"keyTag": 61009,
					"signersName": "example.com",
					"signature": "cAbYvDJhZGLS/uI5I4mSrh7S5gEUy6bmX2sY7zEd1XVFPqrUOZHbVZuwXPjA6r9/m0rCaww9RiG90JhNNDLEtA=="
				},
				"dnssecStatus": "Unknown"
			}
		]
	},
	"status": "ok"
}
```

### Update Record

Updates an existing record in an authoritative zone.

URL:\
`http://localhost:5380/api/zones/records/update?token=x&domain=mail.example.com&zone=example.com&type=A&value=127.0.0.1&newValue=127.0.0.2&ptr=false`

OBSOLETE PATH:\
`/api/zone/updateRecord`\
`/api/updateRecord`

PERMISSIONS:\
Zones: None\
Zone: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `domain`: The domain name of the zone to update the record.
- `zone` (optional): The name of the authoritative zone into which the `domain` exists. When unspecified, the closest authoritative zone will be used.
- `type`: The type of the resource record to update.
- `newDomain` (optional): The new domain name to be set for the record. To be used to rename sub domain name of the record.
- `ttl` (optional): The TTL value of the resource record. Default value of `3600` is used when parameter is missing.
- `disable` (optional): Specifies if the record should be disabled. The default value is `false` when this parameter is missing.
- `comments` (optional): Sets comments for the updated resource record.
- `expiryTtl` (optional): Set to automatically delete the record when the value in seconds elapses since the record’s last modified time.
- `ipAddress` (optional): The current IP address in the `A` or `AAAA` record. This parameter is required when updating `A` or `AAAA` record.
- `newIpAddress` (optional): The new IP address in the `A` or `AAAA` record. This parameter when missing will use the current value in the record.
- `ptr` (optional): Set this option to `true` to specify if the PTR record associated with the `A` or `AAAA` record must also be updated. This option is used only for `A` and `AAAA` records.
- `createPtrZone` (optional): Set this option to `true` to create a reverse zone for PTR record. This option is used only for `A` and `AAAA` records.
- `updateSvcbHints` (optional): Set this option to `true` to update any SVCB/HTTPS records in the zone that has Automatic Hints option enabled and matches its target name with the current record's domain name. This option is used for `A` and `AAAA` records.
- `nameServer` (optional): The current name server domain name. This option is required for updating `NS` record.
- `newNameServer` (optional): The new server domain name. This option is used for updating `NS` record.
- `glue` (optional): The comma separated list of IP addresses set as glue for the NS record. This parameter is used only when updating `NS` record.
- `cname` (optional): The CNAME domain name to update in the existing `CNAME` record.
- `primaryNameServer` (optional): This is the primary name server parameter in the SOA record. This parameter is required when updating the SOA record.
- `responsiblePerson` (optional): This is the responsible person parameter in the SOA record. This parameter is required when updating the SOA record.
- `serial` (optional): This is the serial parameter in the SOA record. This parameter is required when updating the SOA record.
- `refresh` (optional): This is the refresh parameter in the SOA record. This parameter is required when updating the SOA record.
- `retry` (optional): This is the retry parameter in the SOA record. This parameter is required when updating the SOA record.
- `expire` (optional): This is the expire parameter in the SOA record. This parameter is required when updating the SOA record.
- `minimum` (optional): This is the minimum parameter in the SOA record. This parameter is required when updating the SOA record.
- `useSerialDateScheme` (optional):  Set value to `true` to enable using date scheme for SOA serial. This optional parameter is used only with `Primary`, `Forwarder`, and `Catalog` zones. Default value is `false`. This parameter is required when updating the SOA record.
- `ptrName`(optional): The current PTR domain name. This option is required for updating `PTR` record.
- `newPtrName`(optional): The new PTR domain name. This option is required for updating `PTR` record.
- `preference` (optional): The current preference value in an MX record. This parameter when missing will default to `1` value. This parameter is used only when updating `MX` record.
- `newPreference` (optional): The new preference value in an MX record. This parameter when missing will use the old value. This parameter is used only when updating `MX` record.
- `exchange` (optional): The current exchange domain name. This option is required for updating `MX` record.
- `newExchange` (optional): The new exchange domain name. This option is required for updating `MX` record.
- `text` (optional): The current text value. This option is required for updating `TXT` record.
- `newText` (optional): The new text value. This option is required for updating `TXT` record.
- `splitText` (optional): The current split text value. This option is used for updating `TXT` record and is set to `false` when unspecified.
- `newSplitText` (optional): The new split text value. This option is used for updating `TXT` record and is set to current split text value when unspecified.
- `mailbox` (optional): The current email address value. This option is required for updating `RP` record.
- `newMailbox` (optional): The new email address value. This option is used for updating `RP` record and is set to the current value when unspecified.
- `txtDomain` (optional): The current TXT record's domain name value. This option is required for updating `RP` record.
- `newTxtDomain` (optional). The new TXT record's domain name value. This option is used for updating `RP` record and is set to the current value when unspecified.
- `priority` (optional): This is the current priority in the SRV record. This parameter is required when updating the `SRV` record.
- `newPriority` (optional): This is the new priority in the SRV record. This parameter when missing will use the old value. This parameter is used when updating the `SRV` record.
- `weight` (optional): This is the current weight in the SRV record. This parameter is required when updating the `SRV` record.
- `newWeight` (optional): This is the new weight in the SRV record. This parameter when missing will use the old value. This parameter is used when updating the `SRV` record.
- `port` (optional): This is the port parameter in the SRV record. This parameter is required when updating the `SRV` record.
- `newPort` (optional): This is the new value of the port parameter in the SRV record. This parameter when missing will use the old value. This parameter is used to update the port parameter in the `SRV` record.
- `target` (optional): The current target value. This parameter is required when updating the `SRV` record.
- `newTarget` (optional): The new target value. This parameter when missing will use the old value. This parameter is required when updating the `SRV` record.
- `naptrOrder` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewOrder` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrPreference` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewPreference` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrFlags` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewFlags` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrServices` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewServices` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrRegexp` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewRegexp` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `naptrReplacement` (optional): The current value in the NAPTR record. This parameter is required when updating the `NAPTR` record.
- `naptrNewReplacement` (optional): The new value in the NAPTR record. This parameter when missing will use the old value. This parameter is used when updating the `NAPTR` record.
- `dname` (optional): The DNAME domain name. This parameter is required when updating the `DNAME` record.
- `keyTag` (optional): This parameter is required when updating `DS` record.
- `newKeyTag` (optional): This parameter is required when updating `DS` record.
- `algorithm` (optional): This parameter is required when updating `DS` record.
- `newAlgorithm` (optional): This parameter is required when updating `DS` record.
- `digestType` (optional): This parameter is required when updating `DS` record.
- `newDigestType` (optional): This parameter is required when updating `DS` record.
- `digest` (optional): This parameter is required when updating `DS` record.
- `newDigest` (optional): This parameter is required when updating `DS` record.
- `sshfpAlgorithm` (optional): This parameter is required when updating `SSHFP` record.
- `newSshfpAlgorithm` (optional): This parameter is required when updating `SSHFP` record.
- `sshfpFingerprintType` (optional): This parameter is required when updating `SSHFP` record.
- `newSshfpFingerprintType` (optional): This parameter is required when updating `SSHFP` record.
- `sshfpFingerprint` (optional): This parameter is required when updating `SSHFP` record.
- `newSshfpFingerprint` (optional): This parameter is required when updating `SSHFP` record.
- `tlsaCertificateUsage` (optional): This parameter is required when updating `TLSA` record.
- `newTlsaCertificateUsage` (optional): This parameter is required when updating `TLSA` record.
- `tlsaSelector` (optional): This parameter is required when updating `TLSA` record.
- `newTlsaSelector` (optional): This parameter is required when updating `TLSA` record.
- `tlsaMatchingType` (optional): This parameter is required when updating `TLSA` record.
- `newTlsaMatchingType` (optional): This parameter is required when updating `TLSA` record.
- `tlsaCertificateAssociationData` (optional): This parameter is required when updating `TLSA` record.
- `newTlsaCertificateAssociationData` (optional): This parameter is required when updating `TLSA` record.
- `svcPriority` (optional): The priority value for `SVCB` or `HTTPS` record. This parameter is required for updating `SCVB` or `HTTPS` record.
- `newSvcPriority` (optional): The new priority value for `SVCB` or `HTTPS` record. This parameter when missing will use the old value. 
- `svcTargetName` (optional): The target domain name for `SVCB` or `HTTPS` record. This parameter is required for updating `SCVB` or `HTTPS` record.
- `newSvcTargetName` (optional): The new target domain name for `SVCB` or `HTTPS` record. This parameter when missing will use the old value. 
- `svcParams` (optional): The service parameters for `SVCB` or `HTTPS` record which is a pipe separated list of key and value. For example, `alpn|h2,h3|port|53443`. To clear existing values, set it to `false`. This parameter is required for updating `SCVB` or `HTTPS` record.
- `newSvcParams` (optional): The new service parameters for `SVCB` or `HTTPS` record which is a pipe separated list of key and value. To clear existing values, set it to `false`. This parameter when missing will use the old value. 
- `autoIpv4Hint` (optional): Set this option to `true` to enable Automatic Hints for the `ipv4hint` parameter in the `newSvcParams`. This option is valid only for `SVCB` and `HTTPS` records.
- `autoIpv6Hint` (optional): Set this option to `true` to enable Automatic Hints for the `ipv6hint` parameter in the `newSvcParams`. This option is valid only for `SVCB` and `HTTPS` records.
- `uriPriority` (optional): The priority value for the `URI` record. This parameter is required for updating the `URI` record.
- `newUriPriority` (optional): The new priority value for the `URI` record. This parameter when missing will use the old value.
- `uriWeight` (optional): The weight value for the `URI` record. This parameter is required for updating the `URI` record.
- `newUriWeight` (optional): The new weight value for the `URI` record. This parameter when missing will use the old value.
- `uri` (optional): The URI value for the `URI` record. This parameter is required for updating the `URI` record.
- `newUri` (optional): The new URI value for the `URI` record. This parameter when missing will use the old value.
- `flags` (optional): This is the flags parameter in the `CAA` record. This parameter is required when updating the `CAA` record.
- `newFlags` (optional): This is the new value of the flags parameter in the `CAA` record. This parameter is used to update the flags parameter in the `CAA` record.
- `tag` (optional): This is the tag parameter in the `CAA` record. This parameter is required when updating the `CAA` record.
- `newTag` (optional): This is the new value of the tag parameter in the `CAA` record. This parameter is used to update the tag parameter in the `CAA` record.
- `value` (optional): The current value in `CAA` record. This parameter is required when updating the `CAA` record.
- `newValue` (optional): The new value in `CAA` record. This parameter is required when updating the `CAA` record.
- `aname` (optional): The current `ANAME` domain name. This parameter is required when updating the `ANAME` record.
- `newAName` (optional): The new `ANAME` domain name. This parameter is required when updating the `ANAME` record.
- `protocol` (optional): This is the current protocol value in the `FWD` record. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. This parameter is optional and default value `Udp` will be used when updating the `FWD` record.
- `newProtocol` (optional): This is the new protocol value in the `FWD` record. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. This parameter is optional and default value `Udp` will be used when updating the `FWD` record.
- `forwarder` (optional): The current forwarder address. This parameter is required when updating the `FWD` record.
- `newForwarder` (optional): The new forwarder address. This parameter is required when updating the `FWD` record.
- `forwarderPriority` (optional): The current forwarder priority value. This optional parameter is to be used with `FWD` record. When unspecified, the default value of `0` will be used.
- `dnssecValidation` (optional): Set this boolean value to indicate if DNSSEC validation must be done. This optional parameter is to be used with FWD records. Default value is `false`.
- `proxyType` (optional): The type of proxy that must be used for conditional forwarding. This optional parameter is to be used with FWD records. Valid values are [`NoProxy`, `DefaultProxy`, `Http`, `Socks5`]. Default value `DefaultProxy` is used when this parameter is missing.
- `proxyAddress` (optional): The proxy server address to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyPort` (optional): The proxy server port to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyUsername` (optional): The proxy server username to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `proxyPassword` (optional): The proxy server password to use when `proxyType` is configured. This optional parameter is to be used with FWD records.
- `appName` (optional): This parameter is required for updating the `APP` record.
- `classPath` (optional): This parameter is required for updating the `APP` record.
- `recordData` (optional): This parameter is used for updating the `APP` record as per the DNS app requirements.
- `rdata` (optional): This parameter is used for updating unknown i.e. unsupported record types. The value must be formatted as a hex string or a colon separated hex string.
- `newRData` (optional): This parameter is used for updating unknown i.e. unsupported record types. The new value that must be formatted as a hex string or a colon separated hex string.

RESPONSE:
```
{
	"response": {
		"zone": {
			"name": "example.com",
			"type": "Primary",
			"internal": false,
			"dnssecStatus": "SignedWithNSEC",
			"disabled": false
		},
		"updatedRecord": {
			"disabled": false,
			"name": "example.com",
			"type": "SOA",
			"ttl": 900,
			"rData": {
				"primaryNameServer": "server1.home",
				"responsiblePerson": "hostadmin.example.com",
				"serial": 75,
				"refresh": 900,
				"retry": 300,
				"expire": 604800,
				"minimum": 900
			},
			"dnssecStatus": "Unknown",
			"lastUsedOn": "0001-01-01T00:00:00"
		}
	},
	"status": "ok"
}
```

### Delete Record

Deletes a record from an authoritative zone.

URL:\
`http://localhost:5380/api/zones/records/delete?token=x&domain=example.com&zone=example.com&type=A&value=127.0.0.1`

OBSOLETE PATH:\
`/api/zone/deleteRecord`\
`/api/deleteRecord`

PERMISSIONS:\
Zones: None\
Zone: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `domain`: The domain name of the zone to delete the record.
- `zone` (optional): The name of the authoritative zone into which the `domain` exists. When unspecified, the closest authoritative zone will be used.
- `type`: The type of the resource record to delete.
- `ipAddress` (optional): This parameter is required when deleting `A` or `AAAA` record.
- `updateSvcbHints` (optional): Set this option to `true` to update any SVCB/HTTPS records in the zone that has Automatic Hints option enabled and matches its target name with the current record's domain name. This option is used for `A` and `AAAA` records.
- `nameServer` (optional): This parameter is required when deleting `NS` record.
- `ptrName` (optional): This parameter is required when deleting `PTR` record.
- `preference` (optional): This parameter is required when deleting `MX` record.
- `exchange` (optional): This parameter is required when deleting `MX` record.
- `text` (optional): This parameter is required when deleting `TXT` record.
- `splitText` (optional): This parameter is used when deleting `TXT` record. Default value is set to `false` when unspecified.
- `mailbox` (optional): Set an email address for deleting `RP` record.
- `txtDomain` (optional): Set a `TXT` record's domain name for deleting `RP` record.
- `priority` (optional): This parameter is required when deleting the `SRV` record.
- `weight` (optional): This parameter is required when deleting the `SRV` record.
- `port` (optional): This parameter is required when deleting the `SRV` record.
- `target` (optional): This parameter is required when deleting the `SRV` record.
- `naptrOrder` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrPreference` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrFlags` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrServices` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrRegexp` (optional): This parameter is required when deleting the `NAPTR` record.
- `naptrReplacement` (optional): This parameter is required when deleting the `NAPTR` record.
- `keyTag` (optional): This parameter is required when deleting `DS` record.
- `algorithm` (optional): This parameter is required when deleting `DS` record.
- `digestType` (optional): This parameter is required when deleting `DS` record.
- `digest` (optional): This parameter is required when deleting `DS` record.
- `sshfpAlgorithm` (optional): This parameter is required when deleting `SSHFP` record.
- `sshfpFingerprintType` (optional): This parameter is required when deleting `SSHFP` record.
- `sshfpFingerprint` (optional): This parameter is required when deleting `SSHFP` record.
- `tlsaCertificateUsage` (optional): This parameter is required when deleting `TLSA` record.
- `tlsaSelector` (optional): This parameter is required when deleting `TLSA` record.
- `tlsaMatchingType` (optional): This parameter is required when deleting `TLSA` record.
- `tlsaCertificateAssociationData` (optional): This parameter is required when deleting `TLSA` record.
- `svcPriority` (optional): The priority value for `SVCB` or `HTTPS` record. This parameter is required for deleting `SCVB` or `HTTPS` record.
- `svcTargetName` (optional): The target domain name for `SVCB` or `HTTPS` record. This parameter is required for deleting `SCVB` or `HTTPS` record.
- `svcParams` (optional): The service parameters for `SVCB` or `HTTPS` record which is a pipe separated list of key and value. For example, `alpn|h2,h3|port|53443`. To clear existing values, set it to `false`. This parameter is required for deleting `SCVB` or `HTTPS` record.
- `uriPriority` (optional): The priority value in the `URI` record. This parameter is required when deleting the `URI` record.
- `uriWeight` (optional): The weight value in the `URI` record. This parameter is required when deleting the `URI` record.
- `uri` (optional): The URI value in the `URI` record. This parameter is required when deleting the `URI` record.
- `flags` (optional): This is the flags parameter in the `CAA` record. This parameter is required when deleting the `CAA` record.
- `tag` (optional): This is the tag parameter in the `CAA` record. This parameter is required when deleting the `CAA` record.
- `value` (optional): This parameter is required when deleting the `CAA` record.
- `aname` (optional): This parameter is required when deleting the `ANAME` record.
- `protocol` (optional): This is the protocol parameter in the FWD record. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. This parameter is optional and default value `Udp` will be used when deleting the `FWD` record.
- `forwarder` (optional): This parameter is required when deleting the `FWD` record.
- `rdata` (optional): This parameter is used for deleting unknown i.e. unsupported record types. The value must be formatted as a hex string or a colon separated hex string.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

## DNS Cache API Calls

These API calls allow managing the DNS server cache.

### List Cached Zones

List all cached zones.

URL:\
`http://localhost:5380/api/cache/list?token=x&domain=google.com`

OBSOLETE PATH:\
`/api/listCachedZones`

PERMISSIONS:\
Cache: View 

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain` (Optional): The domain name to list records. If not passed, the domain is set to empty string which corresponds to the zone root.
- `direction` (Optional): Allows specifying the direction of browsing the zone. Valid values are [`up`, `down`] and the default value is `down` when parameter is missing. This option allows the server to skip empty labels in the domain name when browsing up or down.

RESPONSE:
```
{
	"response": {
		"domain": "google.com",
		"zones": [],
		"records": [
			{
				"name": "google.com",
				"type": "A",
				"ttl": "283 (4 mins 43 sec)",
				"rData": {
					"value": "216.58.199.174"
				}
			}
		]
	},
	"status": "ok"
}
```

### Delete Cached Zone

Deletes a specific zone from the DNS cache.

URL:\
`http://localhost:5380/api/cache/delete?token=x&domain=google.com`

OBSOLETE PATH:\
`/api/deleteCachedZone`

PERMISSIONS:\
Cache: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name to delete cached records from.

RESPONSE:
```
{
	"status": "ok"
}
```

### Flush DNS Cache

This call clears all the DNS cache from the server forcing the DNS server to make recursive queries again to populate the cache.

URL:\
`http://localhost:5380/api/cache/flush?token=x`

OBSOLETE PATH:\
`/api/flushDnsCache`

PERMISSIONS:\
Cache: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

## Allowed Zones API Calls

These API calls allow managing the Allowed zones.

### List Allowed Zones

List all allowed zones.

URL:\
`http://localhost:5380/api/allowed/list?token=x&domain=google.com`

OBSOLETE PATH:\
`/api/listAllowedZones`

PERMISSIONS:\
Allowed: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `domain` (Optional): The domain name to list records. If not passed, the domain is set to empty string which corresponds to the zone root.
- `direction` (Optional): Allows specifying the direction of browsing the zone. Valid values are [`up`, `down`] and the default value is `down` when parameter is missing. This option allows the server to skip empty labels in the domain name when browsing up or down.

RESPONSE:
```
{
	"response": {
		"domain": "google.com",
		"zones": [],
		"records": [
			{
				"name": "google.com",
				"type": "NS",
				"ttl": "14400 (4 hours)",
				"rData": {
					"value": "server1"
				}
			},
			{
				"name": "google.com",
				"type": "SOA",
				"ttl": "14400 (4 hours)",
				"rData": {
					"primaryNameServer": "server1",
					"responsiblePerson": "hostadmin.server1",
					"serial": 1,
					"refresh": 14400,
					"retry": 3600,
					"expire": 604800,
					"minimum": 900
				}
			}
		]
	},
	"status": "ok"
}
```

### Allow Zone

Adds a domain name into the Allowed Zones.

URL:\
`http://localhost:5380/api/allowed/add?token=x&domain=google.com`

OBSOLETE PATH:\
`/api/allowZone`

PERMISSIONS:\
Allowed: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name for the zone to be added.

RESPONSE:
```
{
	"status": "ok"
}
```

### Delete Allowed Zone

Allows deleting a zone from the Allowed Zones.

URL:\
`http://localhost:5380/api/allowed/delete?token=x&domain=google.com`

OBSOLETE PATH:\
`/api/deleteAllowedZone`

PERMISSIONS:\
Allowed: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name for the zone to be deleted.

RESPONSE:
```
{
	"status": "ok"
}
```

### Flush Allowed Zone

Flushes the Allowed zone to clear all records.

URL:\
`http://localhost:5380/api/allowed/flush?token=x`

OBSOLETE PATH:\
`/api/flushAllowedZone`

PERMISSIONS:\
Allowed: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Import Allowed Zones

Imports domain names into the Allowed Zones.

URL:\
`http://localhost:5380/api/allowed/import?token=x`

OBSOLETE PATH:\
`/api/importAllowedZones`

PERMISSIONS:\
Allowed: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

REQUEST:
This is a `POST` request call where the content type of the request must be `application/x-www-form-urlencoded` and the content must be as shown below:

```
allowedZones=google.com,twitter.com
```

WHERE:
- `allowedZones`: A list of comma separated domain names that are to be imported.

RESPONSE:
```
{
	"status": "ok"
}
```

### Export Allowed Zones

Allows exporting all the zones from the Allowed Zones as a text file.

URL:\
`http://localhost:5380/api/allowed/export?token=x`

OBSOLETE PATH:\
`/api/exportAllowedZones`

PERMISSIONS:\
Allowed: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
Response is a downloadable text file with `Content-Type: text/plain` and `Content-Disposition: attachment`.

## Blocked Zones API Calls

These API calls allow managing the Blocked zones.

### List Blocked Zones

List all blocked zones.

URL:\
`http://localhost:5380/api/blocked/list?token=x&domain=google.com`

OBSOLETE PATH:\
`/api/listBlockedZones`

PERMISSIONS:\
Blocked: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `domain` (Optional): The domain name to list records. If not passed, the domain is set to empty string which corresponds to the zone root.
- `direction` (Optional): Allows specifying the direction of browsing the zone. Valid values are [`up`, `down`] and the default value is `down` when parameter is missing. This option allows the server to skip empty labels in the domain name when browsing up or down.

RESPONSE:
```
{
	"response": {
		"domain": "google.com",
		"zones": [],
		"records": [
			{
				"name": "google.com",
				"type": "NS",
				"ttl": "14400 (4 hours)",
				"rData": {
					"value": "server1"
				}
			},
			{
				"name": "google.com",
				"type": "SOA",
				"ttl": "14400 (4 hours)",
				"rData": {
					"primaryNameServer": "server1",
					"responsiblePerson": "hostadmin.server1",
					"serial": 1,
					"refresh": 14400,
					"retry": 3600,
					"expire": 604800,
					"minimum": 900
				}
			}
		]
	},
	"status": "ok"
}
```

### Block Zone

Adds a domain name into the Blocked Zones.

URL:\
`http://localhost:5380/api/blocked/add?token=x&domain=google.com`

OBSOLETE PATH:\
`/api/blockZone`

PERMISSIONS:\
Blocked: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name for the zone to be added.

RESPONSE:
```
{
	"status": "ok"
}
```

### Delete Blocked Zone

Allows deleting a zone from the Blocked Zones.

URL:\
`http://localhost:5380/api/blocked/delete?token=x&domain=google.com`

OBSOLETE PATH:\
`/api/deleteBlockedZone`

PERMISSIONS:\
Blocked: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `domain`: The domain name for the zone to be deleted.

RESPONSE:
```
{
	"status": "ok"
}
```

### Flush Blocked Zone

Flushes the Blocked zone to clear all records.

URL:\
`http://localhost:5380/api/blocked/flush?token=x`

OBSOLETE PATH:\
`/api/flushBlockedZone`

PERMISSIONS:\
Blocked: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

### Import Blocked Zones

Imports domain names into Blocked Zones.

URL:\
`http://localhost:5380/api/blocked/import?token=x`

OBSOLETE PATH:\
`/api/importBlockedZones`

PERMISSIONS:\
Blocked: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

REQUEST:
This is a `POST` request call where the content type of the request must be `application/x-www-form-urlencoded` and the content must be as shown below:

```
blockedZones=google.com,twitter.com
```

WHERE:
- `blockedZones`: A list of comma separated domain names that are to be imported.

RESPONSE:
```
{
	"status": "ok"
}
```

### Export Blocked Zones

Allows exporting all the zones from the Blocked Zones as a text file.

URL:\
`http://localhost:5380/api/blocked/export?token=x`

OBSOLETE PATH:\
`/api/exportBlockedZones`

PERMISSIONS:\
Blocked: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
Response is a downloadable text file with `Content-Type: text/plain` and `Content-Disposition: attachment`.

## DNS Apps API Calls

These API calls allows managing DNS Apps.

### List Apps

Lists all installed apps on the DNS server. If the DNS server has Internet access and is able to retrieve data from DNS App Store, the API call will also return if a store App has updates available.

URL:\
`http://localhost:5380/api/apps/list?token=x`

PERMISSIONS:\
Apps/Zones/Logs: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {
		"apps": [
			{
				"name": "Block Page",
				"version": "1.0",
				"dnsApps": [
					{
						"classPath": "BlockPageWebServer.App",
						"description": "Serves a block page from a built-in web server that can be displayed to the end user when a website is blocked by the DNS server.\n\nNote: You need to manually configure the custom IP addresses of this built-in web server in the blocking settings for the block page to be served.",
						"isAppRecordRequestHandler": false,
						"isRequestController": false,
						"isAuthoritativeRequestHandler": false,
						"isRequestBlockingHandler": false,
						"isQueryLogger": false,
						"isPostProcessor": false
					}
				]
			},
			{
				"name": "What Is My DNS",
				"version": "2.0",
				"dnsApps": [
					{
						"classPath": "WhatIsMyDns.App",
						"description": "Returns the IP address of the user's DNS Server for A, AAAA, and TXT queries.",
						"isAppRecordRequestHandler": true,
						"recordDataTemplate": null,
						"isRequestController": false,
						"isAuthoritativeRequestHandler": false,
						"isRequestBlockingHandler": false,
						"isQueryLogger": false,
						"isPostProcessor": false
					}
				]
			}
		]
	},
	"status": "ok"
}
```

### List Store Apps

Lists all available apps on the DNS App Store.

URL:\
`http://localhost:5380/api/apps/listStoreApps?token=x`

PERMISSIONS:\
Apps: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {
		"storeApps": [
			{
				"name": "Geo Continent",
				"version": "1.1",
				"description": "Returns A or AAAA records, or CNAME record based on the continent the client queries from using MaxMind GeoIP2 Country database. This app requires MaxMind GeoIP2 database and includes the GeoLite2 version for trial. To update the MaxMind GeoIP2 database for your app, download the GeoIP2-Country.mmdb file from MaxMind and zip it. Use the zip file with the manual Update option.",
				"url": "https://download.technitium.com/dns/apps/GeoContinentApp.zip",
				"size": "2.01 MB",
				"installed": false
			},
			{
				"name": "Geo Country",
				"version": "1.1",
				"description": "Returns A or AAAA records, or CNAME record based on the country the client queries from using MaxMind GeoIP2 Country database. This app requires MaxMind GeoIP2 database and includes the GeoLite2 version for trial. To update the MaxMind GeoIP2 database for your app, download the GeoIP2-Country.mmdb file from MaxMind and zip it. Use the zip file with the manual Update option.",
				"url": "https://download.technitium.com/dns/apps/GeoCountryApp.zip",
				"size": "2.01 MB",
				"installed": false
			},
			{
				"name": "Geo Distance",
				"version": "1.1",
				"description": "Returns A or AAAA records, or CNAME record of the server located geographically closest to the client using MaxMind GeoIP2 City database. This app requires MaxMind GeoIP2 database and includes the GeoLite2 version for trial. To update the MaxMind GeoIP2 database for your app, download the GeoIP2-City.mmdb file from MaxMind and zip it. Use the zip file with the manual Update option.",
				"url": "https://download.technitium.com/dns/apps/GeoDistanceApp.zip",
				"size": "28.6 MB",
				"installed": false
			},
			{
				"name": "Split Horizon",
				"version": "1.1",
				"description": "Returns different set of A or AAAA records, or CNAME record for clients querying over public and private networks.",
				"url": "https://download.technitium.com/dns/apps/SplitHorizonApp.zip",
				"size": "11.1 KB",
				"installed": true,
				"installedVersion": "1.1",
				"updateAvailable": false
			},
			{
				"name": "What Is My Dns",
				"version": "1.1",
				"description": "Returns the IP address of the user's DNS Server for A, AAAA, and TXT queries.",
				"url": "https://download.technitium.com/dns/apps/WhatIsMyDnsApp.zip",
				"size": "8.79 KB",
				"installed": true,
				"installedVersion": "1.1",
				"updateAvailable": false
			}
		]
	},
	"status": "ok"
}
```

### Download And Install App

Download an app zip file from given URL and installs it on the DNS Server.

URL:\
`http://localhost:5380/api/apps/downloadAndInstall?token=x&name=app-name&url=https://example.com/app.zip`

PERMISSIONS:\
Apps: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to install.
- `url`: The URL of the app zip file. URL must start with `https://`.

RESPONSE:
```
{
	"response": {
		"installedApp": {
			"name": "Wild IP",
			"version": "1.0",
			"dnsApps": [
				{
					"classPath": "WildIp.App",
					"description": "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io.",
					"isAppRecordRequestHandler": true,
					"recordDataTemplate": null,
					"isRequestController": false,
					"isAuthoritativeRequestHandler": false,
					"isRequestBlockingHandler": false,
					"isQueryLogger": false,
					"isPostProcessor": false
				}
			]
		}
	},
	"status": "ok"
}
```

### Download And Update App

Download an app zip file from given URL and updates an existing app installed on the DNS Server.

URL:\
`http://localhost:5380/api/apps/downloadAndUpdate?token=x&name=app-name&url=https://example.com/app.zip`

PERMISSIONS:\
Apps: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to install.
- `url`: The URL of the app zip file. URL must start with `https://`.

RESPONSE:
```
{
	"response": {
		"updatedApp": {
			"name": "Wild IP",
			"version": "1.0",
			"dnsApps": [
				{
					"classPath": "WildIp.App",
					"description": "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io.",
					"isAppRecordRequestHandler": true,
					"recordDataTemplate": null,
					"isRequestController": false,
					"isAuthoritativeRequestHandler": false,
					"isRequestBlockingHandler": false,
					"isQueryLogger": false,
					"isPostProcessor": false
				}
			]
		}
	},
	"status": "ok"
}
```

### Install App

Installs a DNS application on the DNS server.

URL:\
`http://localhost:5380/api/apps/install?token=x&name=app-name`

PERMISSIONS:\
Apps: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to install.

REQUEST: This is a POST request call where the request must be multi-part form data with the DNS application zip file data in binary format.

RESPONSE:
```
{
	"response": {
		"installedApp": {
			"name": "Wild IP",
			"version": "1.0",
			"dnsApps": [
				{
					"classPath": "WildIp.App",
					"description": "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io.",
					"isAppRecordRequestHandler": true,
					"recordDataTemplate": null,
					"isRequestController": false,
					"isAuthoritativeRequestHandler": false,
					"isRequestBlockingHandler": false,
					"isQueryLogger": false,
					"isPostProcessor": false
				}
			]
		}
	},
	"status": "ok"
}
```

### Update App

Allows to manually update an installed app using a provided app zip file.

URL:\
`http://localhost:5380/api/apps/update?token=x&name=app-name`

PERMISSIONS:\
Apps: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to update.

REQUEST: This is a POST request call where the request must be multi-part form data with the DNS application zip file data in binary format.

RESPONSE:
```
{
	"response": {
		"updatedApp": {
			"name": "Wild IP",
			"version": "1.0",
			"dnsApps": [
				{
					"classPath": "WildIp.App",
					"description": "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io.",
					"isAppRecordRequestHandler": true,
					"recordDataTemplate": null,
					"isRequestController": false,
					"isAuthoritativeRequestHandler": false,
					"isRequestBlockingHandler": false,
					"isQueryLogger": false,
					"isPostProcessor": false
				}
			]
		}
	},
	"status": "ok"
}
```

### Uninstall App

Uninstall an app from the DNS server. This does not remove any APP records that were using this DNS application.

URL:\
`http://localhost:5380/api/apps/uninstall?token=x&name=app-name`

PERMISSIONS:\
Apps: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to uninstall.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Get App Config

Retrieve the DNS application config from the `dnsApp.config` file in the application folder.

URL:\
`http://localhost:5380/api/apps/config/get?token=x&name=app-name`

OBSOLETE PATH:\
`/api/apps/getConfig`

PERMISSIONS:\
Apps: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `name`: The name of the app to retrieve the config.

RESPONSE:
```
{
	"response": {
		"config": "config data or `null`"
	},
	"status": "ok"
}
```

### Set App Config

Saves the provided DNS application config into the `dnsApp.config` file in the application folder.

URL:\
`http://localhost:5380/api/apps/config/set?token=x&name=app-name`

OBSOLETE PATH:\
`/api/apps/setConfig`

PERMISSIONS:\
Apps: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the app to retrieve the config.

REQUEST: This is a POST request call where the content type of the request must be `application/x-www-form-urlencoded` and the content must be as shown below:
```
config=query-string-encoded-config-data
```

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

## DNS Client API Calls

These API calls allow interacting with the DNS Client section.

### Resolve Query

URL:\
`http://localhost:5380/api/dnsClient/resolve?token=x&server=this-server&domain=example.com&type=A&protocol=UDP`

OBSOLETE PATH:\
`/api/resolveQuery`

PERMISSIONS:\
DnsClient: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `server`: The name server to query using the DNS client. Use `recursive-resolver` to perform recursive resolution. Use `system-dns` to query the DNS servers configured on the system.
- `domain`: The domain name to query.
- `type`: The type of the query.
- `protocol` (optional): The DNS transport protocol to be used to query. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`]. The default value of `Udp` is used when the parameter is missing.
- `dnssec` (optional): Set to `true` to enable DNSSEC validation.
- `eDnsClientSubnet` (optional): The network address to be used with EDNS Client Subnet option in the request.
- `import` (optional): This parameter when set to `true` indicates that the response of the DNS query should be imported in the an authoritative zone on this DNS server. Default value is `false` when this parameter is missing. If a zone does not exists, a primary zone for the `domain` name is created and the records from the response are set into the zone. Import can be done only for primary and forwarder type of zones. When `type` is set to AXFR, then the import feature will work as if a zone transfer was requested and the complete zone will be updated as per the zone transfer response. Note that any existing record type for the given `type` will be overwritten when syncing the records. It is recommended to use `recursive-resolver` or the actual name server address for the `server` parameter when importing records. You must have Zones Modify permission to create a zone or Zone Modify permission to import records into an existing zone.

RESPONSE:
```
{
	"response": {
		"result": {
			"Metadata": {
				"NameServer": "server1:53 (127.0.0.1:53)",
				"Protocol": "Udp",
				"DatagramSize": "45 bytes",
				"RoundTripTime": "1.42 ms"
			},
			"Identifier": 60127,
			"IsResponse": true,
			"OPCODE": "StandardQuery",
			"AuthoritativeAnswer": true,
			"Truncation": false,
			"RecursionDesired": true,
			"RecursionAvailable": true,
			"Z": 0,
			"AuthenticData": false,
			"CheckingDisabled": false,
			"RCODE": "NoError",
			"QDCOUNT": 1,
			"ANCOUNT": 1,
			"NSCOUNT": 0,
			"ARCOUNT": 0,
			"Question": [
				{
					"Name": "example.com",
					"Type": "A",
					"Class": "IN"
				}
			],
			"Answer": [
				{
					"Name": "example.com",
					"Type": "A",
					"Class": "IN",
					"TTL": "86400 (1 day)",
					"RDLENGTH": "4 bytes",
					"RDATA": {
						"IPAddress": "127.0.0.1"
					}
				}
			],
			"Authority": [],
			"Additional": []
		},
		"rawResponses": []
	},
	"status": "ok"
}
```

## Settings API Calls

These API calls allow managing the DNS server settings.

### Get DNS Settings

This call returns all the DNS server settings.

URL:\
`http://localhost:5380/api/settings/get?token=x`

OBSOLETE PATH:\
`/api/getDnsSettings`

PERMISSIONS:\
Settings: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"version": "14.0",
		"uptimestamp": "2025-05-31T10:28:21.6864142Z",
		"dnsServerDomain": "server1",
		"dnsServerLocalEndPoints": [
			"0.0.0.0:53",
			"[::]:53"
		],
		"dnsServerIPv4SourceAddresses": [
			"0.0.0.0"
		],
		"dnsServerIPv6SourceAddresses": [
			"::"
		],
		"defaultRecordTtl": 3600,
		"defaultResponsiblePerson": null,
		"useSoaSerialDateScheme": false,
		"minSoaRefresh": 300,
		"minSoaRetry": 300,
		"zoneTransferAllowedNetworks": [],
		"notifyAllowedNetworks": [],
		"dnsAppsEnableAutomaticUpdate": true,
		"preferIPv6": false,
		"enableUdpSocketPool": false,
		"socketPoolExcludedPorts": [
			53443
		],
		"udpPayloadSize": 1232,
		"dnssecValidation": true,
		"eDnsClientSubnet": false,
		"eDnsClientSubnetIPv4PrefixLength": 24,
		"eDnsClientSubnetIPv6PrefixLength": 56,
		"eDnsClientSubnetIpv4Override": null,
		"eDnsClientSubnetIpv6Override": null,
		"qpmPrefixLimitsIPv4": [
			{
				"prefix": 32,
				"udpLimit": 600,
				"tcpLimit": 600
			},
			{
				"prefix": 24,
				"udpLimit": 6000,
				"tcpLimit": 6000
			}
		],
		"qpmPrefixLimitsIPv6": [
			{
				"prefix": 128,
				"udpLimit": 600,
				"tcpLimit": 600
			},
			{
				"prefix": 64,
				"udpLimit": 1200,
				"tcpLimit": 1200
			},
			{
				"prefix": 56,
				"udpLimit": 6000,
				"tcpLimit": 6000
			}
		],
		"qpmLimitSampleMinutes": 5,
		"qpmLimitUdpTruncationPercentage": 50,
		"qpmLimitBypassList": [],
		"clientTimeout": 2000,
		"tcpSendTimeout": 10000,
		"tcpReceiveTimeout": 10000,
		"quicIdleTimeout": 60000,
		"quicMaxInboundStreams": 100,
		"listenBacklog": 100,
		"maxConcurrentResolutionsPerCore": 100,
		"webServiceLocalAddresses": [
			"[::]"
		],
		"webServiceHttpPort": 5380,
		"webServiceEnableTls": true,
		"webServiceEnableHttp3": false,
		"webServiceHttpToTlsRedirect": false,
		"webServiceUseSelfSignedTlsCertificate": true,
		"webServiceTlsPort": 53443,
		"webServiceTlsCertificatePath": null,
		"webServiceTlsCertificatePassword": "************",
		"webServiceRealIpHeader": "X-Real-IP",
		"enableDnsOverUdpProxy": false,
		"enableDnsOverTcpProxy": false,
		"enableDnsOverHttp": false,
		"enableDnsOverTls": false,
		"enableDnsOverHttps": false,
		"enableDnsOverHttp3": false,
		"enableDnsOverQuic": false,
		"dnsOverUdpProxyPort": 538,
		"dnsOverTcpProxyPort": 538,
		"dnsOverHttpPort": 80,
		"dnsOverTlsPort": 853,
		"dnsOverHttpsPort": 443,
		"dnsOverQuicPort": 853,
		"reverseProxyNetworkACL": [],
		"dnsTlsCertificatePath": null,
		"dnsTlsCertificatePassword": "************",
		"dnsOverHttpRealIpHeader": "X-Real-IP",
		"tsigKeys": [
			{
				"keyName": "home",
				"sharedSecret": "E9crgbHbzgEI+e+/pBmARRif70ScKf2sc/FjrgnCWyc=",
				"algorithmName": "hmac-sha256"
			}
		],
		"recursion": "AllowOnlyForPrivateNetworks",
		"recursionNetworkACL": [],
		"randomizeName": false,
		"qnameMinimization": true,
		"resolverRetries": 2,
		"resolverTimeout": 1500,
		"resolverConcurrency": 2,
		"resolverMaxStackCount": 16,
		"saveCache": true,
		"serveStale": true,
		"serveStaleTtl": 259200,
		"serveStaleAnswerTtl": 30,
		"serveStaleResetTtl": 30,
		"serveStaleMaxWaitTime": 1800,
		"cacheMaximumEntries": 10000,
		"cacheMinimumRecordTtl": 10,
		"cacheMaximumRecordTtl": 604800,
		"cacheNegativeRecordTtl": 300,
		"cacheFailureRecordTtl": 10,
		"cachePrefetchEligibility": 2,
		"cachePrefetchTrigger": 9,
		"cachePrefetchSampleIntervalInMinutes": 5,
		"cachePrefetchSampleEligibilityHitsPerHour": 30,
		"enableBlocking": true,
		"allowTxtBlockingReport": true,
		"blockingBypassList": [],
		"blockingType": "NxDomain",
		"blockingAnswerTtl": 30,
		"customBlockingAddresses": [
			"127.0.0.1"
		],
		"blockListUrls": [
			"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			"https://big.oisd.nl/"
		],
		"blockListUpdateIntervalHours": 24,
		"blockListNextUpdatedOn": "2024-02-01T20:15:08.658124Z",
		"proxy": null,
		"forwarders": null,
		"forwarderProtocol": "Udp",
		"concurrentForwarding": true,
		"forwarderRetries": 3,
		"forwarderTimeout": 2000,
		"forwarderConcurrency": 2,
		"enableLogging": true,
		"loggingType": "File",
		"ignoreResolverLogs": false,
		"logQueries": false,
		"useLocalTime": false,
		"logFolder": "logs",
		"maxLogFileDays": 30,
		"enableInMemoryStats": false,
		"maxStatFileDays": 365
	},
	"status": "ok"
}
```

### Set DNS Settings

This call allows to change the DNS server settings. 

Note! Any parameter passed with this API call will overwrite existing value for that parameter. If you wish to append new values instead then you should first call the Get DNS Settings API to get the existing value, append your new value to it, and then pass the updated value with this API call.

URL:\
`http://localhost:5380/api/settings/set?token=x&dnsServerDomain=server1&dnsServerLocalEndPoints=0.0.0.0:53,[::]:53&webServiceLocalAddresses=0.0.0.0,[::]&webServiceHttpPort=5380&webServiceEnableTls=false&webServiceTlsPort=53443&webServiceTlsCertificatePath=&webServiceTlsCertificatePassword=&enableDnsOverHttp=false&enableDnsOverTls=false&enableDnsOverHttps=false&dnsTlsCertificatePath=&dnsTlsCertificatePassword=&preferIPv6=false&logQueries=true&allowRecursion=true&allowRecursionOnlyForPrivateNetworks=true&randomizeName=true&cachePrefetchEligibility=2&cachePrefetchTrigger=9&cachePrefetchSampleIntervalInMinutes=5&cachePrefetchSampleEligibilityHitsPerHour=30&proxyType=socks5&proxyAddress=192.168.10.2&proxyPort=9050&proxyUsername=username&proxyPassword=password&proxyBypass=127.0.0.0/8,169.254.0.0/16,fe80::/10,::1,localhost&forwarders=192.168.10.2&forwarderProtocol=Udp&useNxDomainForBlocking=false&blockListUrls=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts,https://mirror1.malwaredomains.com/files/justdomains,https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt,https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt`

OBSOLETE PATH:\
`/api/setDnsSettings`

PERMISSIONS:\
Settings: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `dnsServerDomain` (optional): The primary domain name used by this DNS Server to identify itself.
- `dnsServerLocalEndPoints` (optional): Local end points are the network interface IP addresses and ports you want the DNS Server to listen for requests. 
- `dnsServerIPv4SourceAddresses` (optional): A comma separated list of IPv4 source addresses that the DNS server must use for making all outbound DNS requests when the server is connected to two or more networks. Network addresses are also accepted. By default, the IPv4 address of the network with a default route will be used as the source address.
- `dnsServerIPv6SourceAddresses` (optional): A comma separated list of IPv6 source addresses that the DNS server must use for making all outbound DNS requests when the server is connected to two or more networks. Network addresses are also accepted. By default, the IPv6 address of the network with a default route will be used as the source address. Note that this option will be used only when `Prefer IPv6` option is enabled.
- `defaultRecordTtl` (optional, cluster parameter): The default TTL value to use if not specified when adding or updating records in a Zone.
- `defaultResponsiblePerson` (optional, cluster parameter): The default SOA Responsible Person email address to use when adding a Primary Zone.
- `useSoaSerialDateScheme` (optional, cluster parameter): The default SOA Serial option to use if not specified when adding a Primary Zone.
- `minSoaRefresh` (optional, cluster parameter): The minimum Refresh interval to be used by Secondary, Stub, Secondary Forwarder, and Secondary Catalog zones. This value will be used if a zone's SOA Refresh value is less than the minimum value. Initial value is `300`.
- `minSoaRetry` (optional, cluster parameter): The minimum Retry interval to be used by Secondary, Stub, Secondary Forwarder, and Secondary Catalog zones zones. This value will be used if a zone's SOA Retry value is less than the minimum value. Initial value is `300`.
- `zoneTransferAllowedNetworks` (optional, cluster parameter): A comma separated list of IP addresses or network addresses that are allowed to perform zone transfer for all zones without any TSIG authentication.
- `notifyAllowedNetworks` (optional, cluster parameter): A comma separated list of IP addresses or network addresses that are allowed to Notify all secondary zones.
- `dnsAppsEnableAutomaticUpdate` (optional, cluster parameter): Set to `true` to allow DNS server to automatically update the DNS Apps from the DNS App Store. The DNS Server will check for updates every 24 hrs when this option is enabled.
- `preferIPv6` (optional): DNS Server will use IPv6 for querying whenever possible with this option enabled. Initial value is `false`.
- `enableUdpSocketPool` (optional): Set this to `true` to enable UDP socket pool. The DNS Server will use UDP socket pool for all outbound DNS-over-UDP requests when enabled.
- `socketPoolExcludedPorts` (optional): A comma separated list of port numbers that must be excluded from being used by the UDP socket pool.
- `udpPayloadSize` (optional, cluster parameter): The maximum EDNS UDP payload size that can be used to avoid IP fragmentation. Valid range is 512-4096 bytes. Initial value is `1232`.
- `dnssecValidation` (optional, cluster parameter): Set this to `true` to enable DNSSEC validation. DNS Server will validate all responses from name servers or forwarders when this option is enabled.
- `eDnsClientSubnet` (optional, cluster parameter): Set this to `true` to enable EDNS Client Subnet. DNS Server will use the public IP address of the request with a prefix length, or the existing Client Subnet option from the request while resolving requests.
- `eDnsClientSubnetIPv4PrefixLength` (optional, cluster parameter): The EDNS Client Subnet IPv4 prefix length to define the client subnet. Initial value is `24`.
- `eDnsClientSubnetIPv6PrefixLength` (optional, cluster parameter): The EDNS Client Subnet IPv6 prefix length to define the client subnet. Initial value is `56`.
- `eDnsClientSubnetIpv4Override` (optional, cluster parameter): The IPv4 network address that must be used as ECS for all outbound requests overriding client's actual subnet.
- `eDnsClientSubnetIpv6Override` (optional, cluster parameter): The IPv6 network address that must be used as ECS for all outbound requests overriding client's actual subnet.
- `qpmPrefixLimitsIPv4` (optional, cluster parameter): A pipe `|` separated multi row list of prefix, udpLimit and tcpLimit. Set this parameter to `false` to remove all entries. The maximum queries an IPv4 client subnet can make to DNS-over-UDP and DNS-over-TCP protocol services per minute on average based on the sample size. Set limit value to 0 to allow unlimited queries. 
- `qpmPrefixLimitsIPv6` (optional, cluster parameter): A pipe `|` separated multi row list of prefix, udpLimit and tcpLimit. Set this parameter to `false` to remove all entries. The maximum queries an IPv6 client subnet can make to DNS-over-UDP and DNS-over-TCP protocol services per minute on average based on the sample size. Set limit value to 0 to allow unlimited queries. 
- `qpmLimitSampleMinutes` (optional, cluster parameter): Sets the client query stats sample size in minutes for QPM limit feature. Initial value is `5`.
- `qpmLimitUdpTruncationPercentage` (optional, cluster parameter): The percentage of requests that are responded with a truncation (TC) response when QPM limit exceeds for DNS-over-UDP protocol service while the rest of the requests are dropped. A TC response will cause a real client to retry to DNS-over-TCP protocol service. Valid range is `0`-`100`. Initial value is `50`.
- `qpmLimitBypassList` (optional, cluster parameter): A comma separated list of IP addresses or network addresses that are allowed to bypass the QPM limit.
- `clientTimeout` (optional, cluster parameter): The amount of time the DNS server must wait in milliseconds before responding with a ServerFailure response to a client request when no answer is available. Valid range is `1000`-`10000`. Initial value is `4000`.
- `tcpSendTimeout` (optional, cluster parameter): The maximum amount of time in milliseconds a TCP socket will wait for the response to be sent. This option will apply for DNS requests being received by the DNS Server over TCP, TLS, TcpProxy, or HTTPS transports. Valid range is `1000`-`90000`. Initial value is `10000`.
- `tcpReceiveTimeout` (optional, cluster parameter): The maximum amount of time in milliseconds a TCP socket will wait for receiving data. This option will apply for DNS requests being received by the DNS Server over TCP, TLS, TcpProxy, or HTTPS transports. Valid range is `1000`-`90000`. Initial value is `10000`.
- `quicIdleTimeout` (optional, cluster parameter): The time interval in milliseconds after which an idle QUIC connection will be closed. This option applies only to QUIC transport protocol. Valid range is `1000`-`90000`. Initial value is `60000`.
- `quicMaxInboundStreams` (optional, cluster parameter): The max number of inbound bidirectional streams that can be accepted per QUIC connection. This option applies only to QUIC transport protocol. Valid range is `1`-`1000`. Initial value is `100`.
- `listenBacklog` (optional, cluster parameter): The maximum number of pending inbound connections. This option applies to TCP, TLS, TcpProxy, and QUIC transport protocols. Initial value is `100`.
- `maxConcurrentResolutionsPerCore` (optional, cluster parameter): The maximum number of concurrent async outbound resolutions that should be done per CPU core.  Initial value is `100`.
- `webServiceLocalAddresses` (optional): Local addresses are the network interface IP addresses you want the web service to listen for requests. 
- `webServiceHttpPort` (optional): Specify the TCP port number for the web console and this API web service. Initial value is `5380`.
- `webServiceEnableTls` (optional): Set this to `true` to start the HTTPS service to access web service.
- `webServiceEnableHttp3` (optional): Set this to `true` to enable HTTP/3 protocol for the web service.
- `webServiceHttpToTlsRedirect` (optional): Set this option to `true` to enable HTTP to HTTPS Redirection.
- `webServiceTlsPort` (optional): Specified the TCP port number for the web console for HTTPS access.
- `webServiceUseSelfSignedTlsCertificate` (optional): Set `true` for the web service to use an automatically generated self signed certificate when TLS certificate path is not specified.
- `webServiceTlsCertificatePath` (optional): Specify a PKCS #12 certificate (.pfx) file path on the server. The certificate must contain private key. This certificate is used by the web console for HTTPS access.
- `webServiceTlsCertificatePassword` (optional): Enter the certificate (.pfx) password, if any.
- `webServiceRealIpHeader` (optional): The HTTP header that must be used to read client's actual IP address when the request comes from a reverse proxy with a private IP address.
- `enableDnsOverUdpProxy` (optional): Enable this option to accept DNS-over-UDP-PROXY requests. It implements the [PROXY Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for both version 1 & 2 over UDP datagram. Configure the `reverseProxyNetworkACL` option to allow only requests coming from your reverse proxy server.
- `enableDnsOverTcpProxy` (optional): Enable this option to accept DNS-over-TCP-PROXY requests. It implements the [PROXY Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for both version 1 & 2 over TCP connection. Configure the `reverseProxyNetworkACL` option to allow only requests coming from your reverse proxy server.
- `enableDnsOverHttp` (optional): Enable this option to accept DNS-over-HTTP requests. It must be used with a TLS terminating reverse proxy like nginx. Configure the `reverseProxyNetworkACL` option to allow only requests coming from your reverse proxy server. Enabling this option also allows automatic TLS certificate renewal with HTTP challenge (webroot) for DNS-over-HTTPS service.
- `enableDnsOverTls` (optional): Enable this option to accept DNS-over-TLS requests.
- `enableDnsOverHttps` (optional): Enable this option to accept DNS-over-HTTPS requests.
- `enableDnsOverQuic` (optional): Enable this option to accept DNS-over-QUIC requests.
- `dnsOverUdpProxyPort` (optional): The UDP port number for DNS-over-UDP-PROXY protocol. Initial value is `538`.
- `dnsOverTcpProxyPort` (optional): The TCP port number for DNS-over-TCP-PROXY protocol. Initial value is `538`.
- `dnsOverHttpPort` (optional): The TCP port number for DNS-over-HTTP protocol. Initial value is `80`.
- `dnsOverTlsPort` (optional): The TCP port number for DNS-over-TLS protocol. Initial value is `853`.
- `dnsOverHttpsPort` (optional): The TCP port number for DNS-over-HTTPS protocol. Initial value is `443`.
- `dnsOverQuicPort` (optional): The UDP port number for DNS-over-QUIC protocol. Initial value is `853`.
- `reverseProxyNetworkACL` (optional): Configure the ACL to allow only requests coming from your reverse proxy server for DNS-over-UDP-PROXY, DNS-over-TCP-PROXY, and DNS-over-HTTP protocols. Enter IP addresses or network addresses one below another to allow access. Add ! character at the start to deny access, e.g. !192.168.10.0/24 will deny entire subnet. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all.
- `dnsTlsCertificatePath` (optional): Specify a PKCS #12 certificate (.pfx) file path on the server. The certificate must contain private key. This certificate is used by the DNS-over-TLS and DNS-over-HTTPS optional protocols.
- `dnsTlsCertificatePassword` (optional): Enter the certificate (.pfx) password, if any.
- `dnsOverHttpRealIpHeader` (optional): The HTTP header that must be used to read client's actual IP address when the request comes from a reverse proxy with a private IP address.
- `tsigKeys` (optional, cluster parameter): A pipe `|` separated multi row list of TSIG key name, shared secret, and algorithm. Set this parameter to `false` to remove all existing keys. Supported algorithms are [`hmac-md5.sig-alg.reg.int`, `hmac-sha1`, `hmac-sha256`, `hmac-sha256-128`, `hmac-sha384`, `hmac-sha384-192`, `hmac-sha512`, `hmac-sha512-256`].
- `recursion` (optional, cluster parameter): Sets the recursion policy for the DNS server. Valid values are [`Deny`, `Allow`, `AllowOnlyForPrivateNetworks`, `UseSpecifiedNetworkACL`].
- `recursionNetworkACL` (optional, cluster parameter): A comma separated Access Control List (ACL) of Network Access Control (NAC) entry. NAC is an IP address or network address to allow. Add `!` at the start of the NAC to deny access. The ACL is processed in the same order its listed. If no networks match, the default policy is to deny all except loopback. Set this parameter to `false` to remove existing values. These values are only used when `recursion` is set to `UseSpecifiedNetworkACL`.
- `randomizeName` (optional, cluster parameter): Enables QNAME randomization [draft-vixie-dnsext-dns0x20-00](https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00) when using UDP as the transport protocol. Initial value is `true`.
- `qnameMinimization` (optional, cluster parameter): Enables QNAME minimization [draft-ietf-dnsop-rfc7816bis-04](https://tools.ietf.org/html/draft-ietf-dnsop-rfc7816bis-04) when doing recursive resolution. Initial value is `true`.
- `resolverRetries` (optional, cluster parameter): The number of retries that the recursive resolver must do.
- `resolverTimeout` (optional, cluster parameter): The timeout value in milliseconds for the recursive resolver.
- `resolverConcurrency` (optional, cluster parameter): The number of concurrent requests that should be sent by the recursive resolver to the name servers.
- `resolverMaxStackCount` (optional, cluster parameter): The max stack count that the recursive resolver must use.
- `saveCache` (optional): Enable this option to save DNS cache on disk when the DNS server stops. The saved cache will be loaded next time the DNS server starts.
- `serveStale` (optional): Enable the serve stale feature to improve resiliency by using expired or stale records in cache when the DNS server is unable to reach the upstream or authoritative name servers. Initial value is `true`.
- `serveStaleTtl` (optional): The TTL value in seconds which should be used for cached records that are expired. When the serve stale TTL too expires for a stale record, it gets removed from the cache. Recommended value is between 1-3 days and maximum supported value is 7 days. Initial value is `259200`.
- `serveStaleAnswerTtl` (optional): The TTL value in seconds which should be used for the records in a stale response. This is the TTL value that the client will be using to cache the stale records. The valid range is 0-300 seconds and recommended value is 30 seconds.
- `serveStaleResetTtl` (optional): The TTL value in seconds which should be used to reset the stale record's TTL value in the cache when the resolver fails to refresh the data. The TTL reset causes the stale records to become valid again so that they can be used to serve requests normally. This reset effectively prevents the resolver from attempting to frequently update the stale records. The valid range is 10-900 seconds and recommended value is 30 seconds.
- `serveStaleMaxWaitTime` (optional): The time in milliseconds that the DNS server must wait for the resolver before serving stale records from the cache. Lower value will ensure faster response at the expense of not getting updated data from the upstream. Setting value to 0 will instantly return stale answer without waiting for the resolver to fetch updates from the upstream. The valid range is 0-1800 milliseconds and default value is 1800 milliseconds.
- `cacheMinimumRecordTtl` (optional): The minimum TTL value that a record can have in cache. Set a value to make sure that the records with TTL value than it stays in cache for a minimum duration. Initial value is `10`.
- `cacheMaximumRecordTtl` (optional): The maximum TTL value that a record can have in cache. Set a lower value to allow the records to expire early. Initial value is `86400`.
- `cacheNegativeRecordTtl` (optional): The negative TTL value to use when there is no SOA MINIMUM value available. Initial value is `300`.
- `cacheFailureRecordTtl` (optional): The failure TTL value to used for caching failure responses. This allows storing failure record in cache and prevent frequent recursive resolution to name servers that are responding with `ServerFailure`. Initial value is `60`.
- `cachePrefetchEligibility` (optional): The minimum initial TTL value of a record needed to be eligible for prefetching.
- `cachePrefetchTrigger` (optional): A record with TTL value less than trigger value will initiate prefetch operation immediately for itself. Set `0` to disable prefetching & auto prefetching.
- `cachePrefetchSampleIntervalInMinutes` (optional): The interval to sample eligible domain names from last hour stats for auto prefetch.
- `cachePrefetchSampleEligibilityHitsPerHour` (optional): Minimum required hits per hour for a domain name to be eligible for auto prefetch.
- `enableBlocking` (optional, cluster parameter): Sets the DNS server to block domain names using Blocked Zone and Block List Zone.
- `allowTxtBlockingReport` (optional, cluster parameter): Specifies if the DNS Server should respond with TXT records containing a blocked domain report for TXT type requests.
- `blockingBypassList` (optional, cluster parameter): A comma separated list of IP addresses or network addresses that are allowed to bypass blocking.
- `blockingType` (optional, cluster parameter): Sets how the DNS server should respond to a blocked domain request. Valid values are [`AnyAddress`, `NxDomain`, `CustomAddress`] where `AnyAddress` is default which response with `0.0.0.0` and `::` IP addresses for blocked domains. Using `NxDomain` will respond with `NX Domain` response. `CustomAddress` will return the specified custom blocking addresses.
- `blockingAnswerTtl` (optional, cluster parameter): The TTL value in seconds that must be used for the records in a blocking response. This is the TTL value that the client will use to cache the blocking response.
- `customBlockingAddresses` (optional, cluster parameter): Set the custom blocking addresses to be used for blocked domain response. These addresses are returned only when `blockingType` is set to `CustomAddress`.
- `blockListUrls` (optional, cluster parameter): A comma separated list of block list URLs that this server must automatically download and use with the block lists zone. DNS Server will use the data returned by the block list URLs to update the block list zone automatically every 24 hours. The expected file format is standard hosts file format or plain text file containing list of domains to block. Set this parameter to `false` to remove existing values.
- `blockListUpdateIntervalHours` (optional, cluster parameter): The interval in hours to automatically download and update the block lists. Initial value is `24`.
- `proxyType` (optional, cluster parameter): The type of proxy protocol to be used. Valid values are [`None`, `Http`, `Socks5`].
- `proxyAddress` (optional, cluster parameter): The proxy server hostname or IP address.
- `proxyPort` (optional, cluster parameter): The proxy server port.
- `proxyUsername` (optional, cluster parameter): The proxy server username.
- `proxyPassword` (optional, cluster parameter): The proxy server password.
- `proxyBypass` (optional, cluster parameter): A comma separated bypass list consisting of IP addresses, network addresses in CIDR format, or host/domain names to never use proxy for.
- `forwarders` (optional, cluster parameter): A comma separated list of forwarders to be used by this DNS server. Set this parameter to `false` string to remove existing forwarders so that the DNS server does recursive resolution by itself.
- `forwarderProtocol` (optional, cluster parameter): The forwarder DNS transport protocol to be used. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`].
- `concurrentForwarding` (optional, cluster parameter): Set this option to `true` to allow querying two or more forwarders concurrently instead of sequentially querying them in their given order. The DNS server will automatically select forwarders (based on their average latency) to query and use the fastest response it receives from any of them. If none of the selected forwarders respond in time, the DNS server will similarly select forwarders from the remaining ones and queries them till all are tried before giving up.
- `forwarderRetries` (optional, cluster parameter): The number of retries that the forwarder DNS client must do.
- `forwarderTimeout` (optional, cluster parameter): The timeout value in milliseconds for the forwarder DNS client.
- `forwarderConcurrency` (optional, cluster parameter): The number of concurrent requests that the forwarder DNS client should do.
- `loggingType` (optional): Specifies how the error logs and audit logs are written. The valid values are [`None`, `File`, `Console`, `FileAndConsole`]. Initial value is `File`.
- `enableLogging` (optional)(obsolete, use `loggingType` instead): Enable this option to log error and audit logs into the log file. Initial value is `true`.
- `ignoreResolverLogs` (optional): Enable this option to stop logging domain name resolution errors into the log file.
- `logQueries` (optional): Enable this option to log every query received by this DNS Server and the corresponding response answers into the log file.  Initial value is `false`.
- `useLocalTime` (optional): Enable this option to use local time instead of UTC for logging.  Initial value is `false`.
- `logFolder` (optional): The folder path on the server where the log files should be saved. The path can be relative to the DNS server config folder. Initial value is `logs`.
- `maxLogFileDays` (optional): Max number of days to keep the log files. Log files older than the specified number of days will be deleted automatically. Recommended value is `365`. Set `0` to disable auto delete.
- `enableInMemoryStats` (optional): Set this option to `true` to enable in-memory stats. When enabled, only Last Hour data will be available on Dashboard and no stats data will be stored on disk.
- `maxStatFileDays` (optional): Max number of days to keep the dashboard stats. Stat files older than the specified number of days will be deleted automatically. Recommended value is `365`. Set `0` to disable auto delete.

NOTE! The parameters marked as a "cluster parameter" are synced automatically across all the Cluster nodes when Clustering is initialized.

REQUEST: Instead of query string or form data parameters described above, the request optionally can also POST settings as JSON data in the same format as returned by `getDnsSettings` API call.

RESPONSE:
This call returns the newly updated settings in the same format as that of the `getDnsSettings` call.

### Get TSIG Key Names

Returns a list of TSIG key names that are configured in the DNS server Settings.

URL:\
`http://localhost:5380/api/settings/getTsigKeyNames?token=x`

PERMISSIONS:\
Settings: View OR Zones: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"tsigKeyNames": [
			"key1",
			"key2"
		]
	},
	"status": "ok"
}
```

### Force Update Block Lists

This call allows to reset the next update schedule and force download and update of the block lists.

URL:\
`http://localhost:5380/api/settings/forceUpdateBlockLists?token=x`

OBSOLETE PATH:\
`/api/forceUpdateBlockLists`

PERMISSIONS:\
Settings: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"status": "ok"
}
```

NOTE! This API call is synced automatically across all Cluster nodes when Clustering is initialized.

### Temporarily Disable Block Lists

This call temporarily disables the block lists and block list zones.

URL:\
`http://localhost:5380/api/settings/temporaryDisableBlocking?token=x&minutes=5`

OBSOLETE PATH:\
`/api/temporaryDisableBlocking`

PERMISSIONS:\
Settings: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `minutes`: The time in minutes to disable the blocklist for.

RESPONSE:
```
{
	"status": "ok",
	"response": {
		"temporaryDisableBlockingTill": "2021-10-10T01:14:27.1106773Z"
	}
}
```

NOTE! This API call is synced automatically across all Cluster nodes when Clustering is initialized.

### Backup Settings

This call returns a zip file containing copies of all the items that were requested to be backed up.

URL:\
`http://localhost:5380/api/settings/backup?token=x&blockLists=true&logs=true&scopes=true&stats=true&zones=true&allowedZones=true&blockedZones=true&dnsSettings=true&logSettings=true&authConfig=true`

OBSOLETE PATH:\
`/api/backupSettings`

PERMISSIONS:\
Settings: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `authConfig` (optional): Set to `true` to backup the authentication config file. Default value is `false`.
- `clusterConfig` (optional): Set to `true` to backup the Cluster config file. Default value is `false`.
- `webServiceConfig` (optional): Set to `true` to backup the web service config file. Default value is `false`.
- `dnsSettings` (optional): Set to `true` to backup DNS settings and certificate files. The Web Service or Optional Protocols TLS certificate (.pfx) files will be included in the backup only if they exist within the DNS server's config folder. Default value is `false`.
- `logSettings` (optional): Set to `true` to backup log settings file. Default value is `false`.
- `zones` (optional): Set to `true` to backup DNS zone files. Default value is `false`.
- `allowedZones` (optional): Set to `true` to backup allowed zones file. Default value is `false`.
- `blockedZones` (optional): Set to `true` to backup blocked zones file. Default value is `false`.
- `blockLists` (optional): Set to `true` to backup block lists cache files. Default value is `false`.
- `apps` (optional): Set to `true` to backup the installed DNS apps. Default value is `false`.
- `scopes` (optional): Set to `true` to backup DHCP scope files. Default value is `false`.
- `stats` (optional): Set to `true` to backup dashboard stats files. Default value is `false`.
- `logs` (optional): Set to `true` to backup log files. Default value is `false`.

RESPONSE:
A zip file with content type `application/zip` and content disposition set to `attachment`.

### Restore Settings

This call restores selected items from a given backup zip file.

URL:\
`http://localhost:5380/api/settings/restore?token=x&blockLists=true&logs=true&scopes=true&stats=true&zones=true&allowedZones=true&blockedZones=true&dnsSettings=true&logSettings=true&deleteExistingFiles=true&authConfig=true`

OBSOLETE PATH:\
`/api/restoreSettings`

PERMISSIONS:\
Settings: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `authConfig` (optional): Set to `true` to restore the authentication config file. Default value is `false`.
- `clusterConfig` (optional): Set to `true` to restore the Cluster config file. Default value is `false`.
- `webServiceConfig` (optional): Set to `true` to restore the web service config file. Default value is `false`.
- `dnsSettings` (optional): Set to `true` to restore DNS settings and certificate files. Default value is `false`.
- `logSettings` (optional): Set to `true` to restore log settings file. Default value is `false`.
- `zones` (optional): Set to `true` to restore DNS zone files. Default value is `false`.
- `allowedZones` (optional): Set to `true` to restore allowed zones file. Default value is `false`.
- `blockedZones` (optional): Set to `true` to restore blocked zones file. Default value is `false`.
- `blockLists` (optional): Set to `true` to restore block lists cache files. Default value is `false`.
- `apps` (optional): Set to `true` to restore the DNS apps. Default value is `false`.
- `scopes` (optional): Set to `true` to restore DHCP scope files. Default value is `false`.
- `stats` (optional): Set to `true` to restore dashboard stats files. Default value is `false`.
- `logs` (optional): Set to `true` to restore log files. Default value is `false`.
- `deleteExistingFiles` (optional). Set to `true` to delete existing files for selected items. Default value is `false`.

REQUEST:
This is a `POST` request call where the request must be multi-part form data with the backup zip file data in binary format.

RESPONSE:
This call returns the newly updated settings in the same format as that of the `getDnsSettings` call.

## DHCP API Calls

Allows managing the built-in DHCP server.

### List DHCP Leases

Lists all the DHCP leases.

URL:\
`http://localhost:5380/api/dhcp/leases/list?token=x`

OBSOLETE PATH:\
`/api/listDhcpLeases`

PERMISSIONS:\
DhcpServer: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"leases": [
			{
				"scope": "Default",
				"type": "Reserved",
				"hardwareAddress": "00-00-00-00-00-00",
				"clientIdentifier": "1-000000000000",
				"address": "192.168.1.5",
				"hostName": "server1.local",
				"leaseObtained": "08/25/2020 17:52:51",
				"leaseExpires": "09/26/2020 14:27:12"
			},
			{
				"scope": "Default",
				"type": "Dynamic",
				"hardwareAddress": "00-00-00-00-00-00",
				"clientIdentifier": "1-000000000000",
				"address": "192.168.1.13",
				"hostName": null,
				"leaseObtained": "06/15/2020 16:41:46",
				"leaseExpires": "09/25/2020 12:39:54"
			},
			{
				"scope": "Default",
				"type": "Dynamic",
				"hardwareAddress": "00-00-00-00-00-00",
				"clientIdentifier": "1-000000000000",
				"address": "192.168.1.15",
				"hostName": "desktop-ea2miaf.local",
				"leaseObtained": "06/18/2020 12:19:03",
				"leaseExpires": "09/25/2020 12:17:11"
			},
		]
	},
	"status": "ok"
}
```

### Remove DHCP Lease

Removes a dynamic or reserved lease allocation. This API must be used carefully to make sure that there is no IP address conflict caused by removing a lease.

URL:\
`http://localhost:5380/api/dhcp/leases/remove?token=x&name=Default&hardwareAddress=00:00:00:00:00:00`

OBSOLETE PATH:\
`/api/removeDhcpLease`

PERMISSIONS:\
DhcpServer: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.
- `clientIdentifier` (optional): The client identifier for the lease. Either `hardwareAddress` or `clientIdentifier` must be specified.
- `hardwareAddress` (optional): The MAC address of the device bearing the dynamic/reserved lease. Either `hardwareAddress` or `clientIdentifier` must be specified.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Convert To Reserved Lease

Converts a dynamic lease to reserved lease.

URL:\
`http://localhost:5380/api/dhcp/leases/convertToReserved?token=x&name=Default&hardwareAddress=00:00:00:00:00:00`

OBSOLETE PATH:\
`/api/convertToReservedLease`

PERMISSIONS:\
DhcpServer: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.
- `clientIdentifier` (optional): The client identifier for the lease. Either `hardwareAddress` or `clientIdentifier` must be specified.
- `hardwareAddress` (optional): The MAC address of the device bearing the dynamic lease. Either `hardwareAddress` or `clientIdentifier` must be specified.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Convert To Dynamic Lease

Converts a reserved lease to dynamic lease.

URL:\
`http://localhost:5380/api/dhcp/leases/convertToDynamic?token=x&name=Default&hardwareAddress=00:00:00:00:00:00`

OBSOLETE PATH:\
`/api/convertToDynamicLease`

PERMISSIONS:\
DhcpServer: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.
- `clientIdentifier` (optional): The client identifier for the lease. Either `hardwareAddress` or `clientIdentifier` must be specified.
- `hardwareAddress` (optional): The MAC address of the device bearing the reserved lease. Either `hardwareAddress` or `clientIdentifier` must be specified.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### List DHCP Scopes

Lists all the DHCP scopes available on the server.

URL:\
`http://localhost:5380/api/dhcp/scopes/list?token=x`

OBSOLETE PATH:\
`/api/listDhcpScopes`

PERMISSIONS:\
DhcpServer: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.

RESPONSE:
```
{
	"response": {
		"scopes": [
			{
				"name": "Default",
				"enabled": false,
				"startingAddress": "192.168.1.1",
				"endingAddress": "192.168.1.254",
				"subnetMask": "255.255.255.0",
				"networkAddress": "192.168.1.0",
				"broadcastAddress": "192.168.1.255"
			}
		]
	},
	"status": "ok"
}
```

### Get DHCP Scope

Gets the complete details of the scope configuration.

URL:\
`http://localhost:5380/api/dhcp/scopes/get?token=x&name=Default`

OBSOLETE PATH:\
`/api/getDhcpScope`

PERMISSIONS:\
DhcpServer: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.

RESPONSE:
```
{
	"response": {
		"name": "Default",
		"startingAddress": "192.168.1.1",
		"endingAddress": "192.168.1.254",
		"subnetMask": "255.255.255.0",
		"leaseTimeDays": 7,
		"leaseTimeHours": 0,
		"leaseTimeMinutes": 0,
		"offerDelayTime": 0,
		"pingCheckEnabled": false,
		"pingCheckTimeout": 1000,
		"pingCheckRetries": 2,
		"domainName": "local",
		"domainSearchList": [
			"home.arpa",
			"lan"
		],
		"dnsUpdates": true,
		"dnsTtl": 900,
		"serverAddress": "192.168.1.1",
		"serverHostName": "tftp-server-1",
		"bootFileName": "boot.bin",
		"routerAddress": "192.168.1.1",
		"useThisDnsServer": false,
		"dnsServers": [
			"192.168.1.5"
		],
		"winsServers": [
			"192.168.1.5"
		],
		"ntpServers": [
			"192.168.1.5"
		],
		"staticRoutes": [
			{
				"destination": "172.16.0.0",
				"subnetMask": "255.255.255.0",
				"router": "192.168.1.2"
			}
		],
		"vendorInfo": [
			{
				"identifier": "substring(vendor-class-identifier,0,9)==\"PXEClient\"",
				"information": "06:01:03:0A:04:00:50:58:45:09:14:00:00:11:52:61:73:70:62:65:72:72:79:20:50:69:20:42:6F:6F:74:FF"
			}
		],
		"capwapAcIpAddresses": [
			"192.168.1.2"
		],
		"tftpServerAddresses": [
			"192.168.1.5",
			"192.168.1.6"
		],
		"genericOptions": [
			{
				"code": 150,
				"value": "C0:A8:01:01"
			}
		],
		"exclusions": [
			{
				"startingAddress": "192.168.1.1",
				"endingAddress": "192.168.1.10"
			}
		],
		"reservedLeases": [
			{
				"hostName": null,
				"hardwareAddress": "00-00-00-00-00-00",
				"address": "192.168.1.10",
				"comments": "comments"
			}
		],
		"allowOnlyReservedLeases": false,
		"blockLocallyAdministeredMacAddresses": true,
		"ignoreClientIdentifierOption": true
	},
	"status": "ok"
}
```

### Set DHCP Scope

Sets the DHCP scope configuration.

URL:\
`http://localhost:5380/api/dhcp/scopes/set?token=x&name=Default&startingAddress=192.168.1.1&endingAddress=192.168.1.254&subnetMask=255.255.255.0&leaseTimeDays=7&leaseTimeHours=0&leaseTimeMinutes=0&offerDelayTime=0&domainName=local&dnsTtl=900&serverAddress=&serverHostName=&bootFileName=&routerAddress=192.168.1.1&useThisDnsServer=false&dnsServers=192.168.1.5&winsServers=192.168.1.5&ntpServers=192.168.1.5&staticRoutes=172.16.0.0|255.255.255.0|192.168.1.2&exclusions=192.168.1.1|192.168.1.10&reservedLeases=hostname|00-00-00-00-00-00|192.168.1.10|comments&allowOnlyReservedLeases=false`

OBSOLETE PATH:\
`/api/setDhcpScope`

PERMISSIONS:\
DhcpServer: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.
- `newName` (optional): The new name of the DHCP scope to rename an existing scope.
- `startingAddress` (optional): The starting IP address of the DHCP scope. This parameter is required when creating a new scope.
- `endingAddress` (optional): The ending IP address of the DHCP scope. This parameter is required when creating a new scope.
- `subnetMask` (optional): The subnet mask of the network. This parameter is required when creating a new scope.
- `leaseTimeDays` (optional): The lease time in number of days.
- `leaseTimeHours` (optional): The lease time in number of hours.
- `leaseTimeMinutes` (optional): The lease time in number of minutes.
- `offerDelayTime` (optional): The time duration in milliseconds that the DHCP server delays sending an DHCPOFFER message.
- `pingCheckEnabled` (optional): Set this option to `true` to allow the DHCP server to find out if an IP address is already in use to prevent IP address conflict when some of the devices on the network have manually configured IP addresses.
- `pingCheckTimeout` (optional): The timeout interval to wait for an ping reply.
- `pingCheckRetries` (optional): The maximum number of ping requests to try.
- `domainName` (optional): The domain name to be used by this network. The DHCP server automatically adds forward and reverse DNS entries for each IP address allocations when domain name is configured. (Option 15)
- `domainSearchList` (optional): A comma separated list of domain names that the clients can use as a suffix when searching a domain name. (Option 119)
- `dnsUpdates` (optional): Set this option to `true` to allow the DHCP server to automatically update forward and reverse DNS entries for clients.
- `dnsTtl` (optional): The TTL value used for forward and reverse DNS records.
- `serverAddress` (optional): The IP address of next server (TFTP) to use in bootstrap by the clients. If not specified, the DHCP server's IP address is used. (siaddr)
- `serverHostName` (optional): The optional bootstrap server host name to be used by the clients to identify the TFTP server. (sname/Option 66)
- `bootFileName` (optional): The boot file name stored on the bootstrap TFTP server to be used by the clients. (file/Option 67)
- `routerAddress` (optional): The default gateway IP address to be used by the clients. (Option 3)
- `useThisDnsServer` (optional): Tells the DHCP server to use this DNS server's IP address to configure the DNS Servers DHCP option for clients.
- `dnsServers` (optional): A comma separated list of DNS server IP addresses to be used by the clients. This parameter is ignored when `useThisDnsServer` is set to `true`. (Option 6)
- `winsServers` (optional): A comma separated list of NBNS/WINS server IP addresses to be used by the clients. (Option 44)
- `ntpServers` (optional): A comma separated list of Network Time Protocol (NTP) server IP addresses to be used by the clients. (Option 42)
- `ntpServerDomainNames` (optional): Enter NTP server domain names (e.g. pool.ntp.org) above that the DHCP server should automatically resolve and pass the resolved IP addresses to clients as NTP server option. (Option 42)
- `staticRoutes` (optional): A `|` separated list of static routes in format `{destination network address}|{subnet mask}|{router/gateway address}` to be used by the clients for accessing specified destination networks. (Option 121)
- `vendorInfo` (optional): A `|` separated list of vendor information in format `{vendor class identifier}|{vendor specific information}` where `{vendor specific information}` is a colon separated hex string or a normal hex string.
- `capwapAcIpAddresses` (optional): A comma separated list of Control And Provisioning of Wireless Access Points (CAPWAP) Access Controller IP addresses to be used by Wireless Termination Points to discover the Access Controllers to which it is to connect. (Option 138)
- `tftpServerAddresses` (optional): A comma separated list of TFTP Server Address or the VoIP Configuration Server Address. (Option 150)
- `genericOptions` (optional): This feature allows you to define DHCP options that are not yet directly supported. Use a `|` separated list of DHCP option code defined for it and the value in either a colon (:) separated hex string or a normal hex string in format `{option-code}|{hex-string-value}`.
- `exclusions` (optional): A `|` separated list of IP address range in format `{starting address}|{ending address}` that must be excluded or not assigned dynamically to any client by the DHCP server.
- `reservedLeases` (optional): A `|` separated list of reserved IP addresses in format `{host name}|{MAC address}|{reserved IP address}|{comments}` to be assigned to specific clients based on their MAC address.
- `allowOnlyReservedLeases` (optional): Set this parameter to `true` to stop dynamic IP address allocation and allocate only reserved IP addresses.
- `blockLocallyAdministeredMacAddresses` (optional): Set this parameter to `true` to stop dynamic IP address allocation for clients with locally administered MAC addresses. MAC address with 0x02 bit set in the first octet indicate a locally administered MAC address which usually means that the device is not using its original MAC address.
- `ignoreClientIdentifierOption` (optional): Set this parameter to `true` to always use the client's MAC address as the identifier to allocate lease instead of the Client Identifier (Option 61) provided by the client in the request. Changing this option may cause the existing clients to get a different IP lease on renewal.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Add Reserved Lease

Adds a reserved lease entry to the specified scope.

URL:\
`http://localhost:5380/api/dhcp/scopes/addReservedLease?token=x&name=Default&hardwareAddress=00:00:00:00:00:00&ipAddress=192.168.1.11`

PERMISSIONS:\
DhcpServer: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.
- `hardwareAddress`: The MAC address of the client.
- `ipAddress`: The reserved IP address for the client.
- `hostName` (optional): The hostname of the client to override.
- `comments` (optional): Comments for the reserved lease entry.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Remove Reserved Lease

Removed a reserved lease entry from the specified scope.

URL:\
`http://localhost:5380/api/dhcp/scopes/removeReservedLease?token=x&name=Default&hardwareAddress=00:00:00:00:00:00`

PERMISSIONS:\
DhcpServer: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.
- `hardwareAddress`: The MAC address of the client.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Enable DHCP Scope

Enables the DHCP scope allowing the server to allocate leases.

URL:\
`http://localhost:5380/api/dhcp/scopes/enable?token=x&name=Default`

OBSOLETE PATH:\
`/api/enableDhcpScope`

PERMISSIONS:\
DhcpServer: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Disable DHCP Scope

Disables the DHCP scope and stops any further lease allocations.

URL:\
`http://localhost:5380/api/dhcp/scopes/disable?token=x&name=Default`

OBSOLETE PATH:\
`/api/disableDhcpScope`

PERMISSIONS:\
DhcpServer: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Delete DHCP Scope

Permanently deletes the DHCP scope from the disk.

URL:\
`http://localhost:5380/api/dhcp/scopes/delete?token=x&name=Default`

OBSOLETE PATH:\
`/api/deleteDhcpScope`

PERMISSIONS:\
DhcpServer: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `name`: The name of the DHCP scope.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

## Administration API Calls

Allows managing the DNS server administration which includes managing all sessions, users, groups, and permissions.

### List Sessions

Returns a list of active user sessions.

URL:\
`http://localhost:5380/api/admin/sessions/list?token=x`

PERMISSIONS:\
Administration: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": true,
				"partialToken": "272f4890427b9ab5",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-17T13:23:44.9972772Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			},
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "ddfaecb8e9325e77",
				"type": "ApiToken",
				"tokenName": "MyToken1",
				"lastSeen": "2022-09-17T13:22:45.6710766Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		]
	},
	"status": "ok"
}
```

### Create API Token

Allows creating a non-expiring API token that can be used with automation scripts to make API calls. The token allows access to API calls with the same privileges as that of the user and thus its advised to create a separate user with limited permissions required for creating the API token. The token cannot be used to change the user's password, or update the user profile details.

URL:\
`http://localhost:5380/api/admin/sessions/createToken?token=x&user=admin&tokenName=MyToken1`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: The username for the user account for which to generate the API token.
- `tokenName`: The name of the created token to identify its session.

RESPONSE:
```
{
	"response": {
		"username": "admin",
		"tokenName": "MyToken1",
		"token": "ddfaecb8e9325e77865ee7e100f89596a65d3eae0e6dddcb33172355b95a64af"
	},
	"status": "ok"
}
```

### Delete Session

Deletes a specified user's session.

URL:\
`http://localhost:5380/api/admin/sessions/delete?token=x&partialToken=ddfaecb8e9325e77`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `partialToken`: The partial token of the session to delete that was returned by the list of sessions.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### List Users

Returns a list of all users.

URL:\
`http://localhost:5380/api/admin/users/list?token=x`

PERMISSIONS:\
Administration: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {
		"users": [
			{
				"displayName": "Administrator",
				"username": "admin",
				"disabled": false,
				"previousSessionLoggedOn": "2022-09-17T13:20:32.7933783Z",
				"previousSessionRemoteAddress": "127.0.0.1",
				"recentSessionLoggedOn": "2022-09-17T13:22:45.671081Z",
				"recentSessionRemoteAddress": "127.0.0.1"
			},
			{
				"displayName": "Shreyas Zare",
				"username": "shreyas",
				"disabled": false,
				"previousSessionLoggedOn": "0001-01-01T00:00:00Z",
				"previousSessionRemoteAddress": "0.0.0.0",
				"recentSessionLoggedOn": "0001-01-01T00:00:00Z",
				"recentSessionRemoteAddress": "0.0.0.0"
			}
		]
	},
	"status": "ok"
}
```

### Create User

Creates a new user account.

URL:\
`http://localhost:5380/api/admin/users/create?token=x&displayName=User&user=user1&pass=password`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: A unique username for the user account.
- `pass`: A password for the user account.
- `displayName` (optional): The display name for the user account.

RESPONSE:
```
{
	"response": {
		"displayName": "User",
		"username": "user1",
		"disabled": false,
		"previousSessionLoggedOn": "0001-01-01T00:00:00",
		"previousSessionRemoteAddress": "0.0.0.0",
		"recentSessionLoggedOn": "0001-01-01T00:00:00",
		"recentSessionRemoteAddress": "0.0.0.0"
	},
	"status": "ok"
}
```

### Get User Details

Returns a user account profile details.

URL:\
`http://localhost:5380/api/admin/users/get?token=x&user=admin&includeGroups=true

PERMISSIONS:\
Administration: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `user`: The username for the user account.
- `includeGroups` (optional): Set `true` to include a list of groups in response.

RESPONSE:
```
{
	"response": {
		"displayName": "Administrator",
		"username": "admin",
		"totpEnabled": false,
		"disabled": false,
		"previousSessionLoggedOn": "2022-09-16T13:22:45.671Z",
		"previousSessionRemoteAddress": "127.0.0.1",
		"recentSessionLoggedOn": "2022-09-18T09:55:26.9800695Z",
		"recentSessionRemoteAddress": "127.0.0.1",
		"sessionTimeoutSeconds": 1800,
		"memberOfGroups": [
			"Administrators"
		],
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "1f8011516cea27af",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-18T09:55:40.6519988Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			},
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "ddfaecb8e9325e77",
				"type": "ApiToken",
				"tokenName": "MyToken1",
				"lastSeen": "2022-09-17T13:22:45.671Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		],
		"groups": [
			"Administrators",
			"DHCP Administrators",
			"DNS Administrators"
		]
	},
	"status": "ok"
}
```

### Set User Details

Allows changing user account profile details.

URL:\
`http://localhost:5380/api/admin/users/set?token=x&user=admin&displayName=Administrator&disabled=false&sessionTimeoutSeconds=1800&memberOfGroups=Administrators`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: The username for the user account.
- `displayName` (optional): The display name for the user account.
- `newUser` (optional): A new username for renaming the username for the user account.
- `totpEnabled` (optional): Set to `false` to disable 2FA for the user account. The parameter cannot have a `true` value.
- `disabled` (optional): Set `true` to disable the user account and delete all its active sessions.
- `sessionTimeoutSeconds` (optional): A session time out value in seconds for the user account.
- `newPass` (optional): A new password to reset the user account password.
- `iterations` (optional): The number of iterations for PBKDF2 SHA256 password hashing. This is only used with the `newPass` option.
- `memberOfGroups` (optional): A list of comma separated group names that the user must be set as a member.

RESPONSE:
```
{
	"response": {
		"displayName": "Administrator",
		"username": "admin",
		"totpEnabled": false,
		"disabled": false,
		"previousSessionLoggedOn": "2022-09-17T13:22:45.671Z",
		"previousSessionRemoteAddress": "127.0.0.1",
		"recentSessionLoggedOn": "2022-09-18T09:55:26.9800695Z",
		"recentSessionRemoteAddress": "127.0.0.1",
		"sessionTimeoutSeconds": 1800,
		"memberOfGroups": [
			"Administrators"
		],
		"sessions": [
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "1f8011516cea27af",
				"type": "Standard",
				"tokenName": null,
				"lastSeen": "2022-09-18T09:59:19.9034491Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			},
			{
				"username": "admin",
				"isCurrentSession": false,
				"partialToken": "ddfaecb8e9325e77",
				"type": "ApiToken",
				"tokenName": "MyToken1",
				"lastSeen": "2022-09-17T13:22:45.671Z",
				"lastSeenRemoteAddress": "127.0.0.1",
				"lastSeenUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
			}
		]
	},
	"status": "ok"
}
```

### Delete User

Deletes a user account.

URL:\
`http://localhost:5380/api/admin/users/delete?token=x&user=user1`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `user`: The username for the user account to delete.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### List Groups

Returns a list of all groups.

URL:\
`http://localhost:5380/api/admin/groups/list?token=x`

PERMISSIONS:\
Administration: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {
		"groups": [
			{
				"name": "Administrators",
				"description": "Super administrators"
			},
			{
				"name": "DHCP Administrators",
				"description": "DHCP service administrators"
			},
			{
				"name": "DNS Administrators",
				"description": "DNS service administrators"
			}
		]
	},
	"status": "ok"
}
```

### Create Group

Creates a new group.

URL:\
`http://localhost:5380/api/admin/groups/create?token=x&group=Group1&description=My%20description`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `group`: The name of the group to create.
- `description` (optional): The description text for the group.

RESPONSE:
```
{
	"response": {
		"name": "Group1",
		"description": "My description"
	},
	"status": "ok"
}
```

### Get Group Details

Returns the details for a group.

URL:\
`http://localhost:5380/api/admin/groups/get?token=x&group=Administrators&includeUsers=true`

PERMISSIONS:\
Administration: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `group`: The name of the group.
- `includeUsers` (optional): Set `true` to include a list of users in response.

RESPONSE:
```
{
	"response": {
		"name": "Administrators",
		"description": "Super administrators",
		"members": [
			"admin"
		],
		"users": [
			"admin",
			"shreyas"
		]
	},
	"status": "ok"
}
```

### Set Group Details

Allows changing group description or rename a group.

URL:\
`http://localhost:5380/api/admin/groups/set?token=x&group=Administrators&description=Super%20administrators&members=admin`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `group`: The name of the group to update.
- `newGroup` (optional): A new group name to rename the group.
- `description` (optional): A new group description.
- `members` (optional): A comma separated list of usernames to set as the group's members.

RESPONSE:
```
{
	"response": {
		"name": "Administrators",
		"description": "Super administrators",
		"members": [
			"admin"
		]
	},
	"status": "ok"
}
```

### Delete Group

Allows deleting a group.

URL:\
`http://localhost:5380/api/admin/groups/delete?token=x&group=Group1`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `group`: The name of the group to delete.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### List Permissions

URL:\
`http://localhost:5380/api/admin/permissions/list?token=x`

PERMISSIONS:\
Administration: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {
		"permissions": [
			{
				"section": "Dashboard",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Zones",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DHCP Administrators",
						"canView": true,
						"canModify": false,
						"canDelete": false
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Cache",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Allowed",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Blocked",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Apps",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "DnsClient",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DHCP Administrators",
						"canView": true,
						"canModify": false,
						"canDelete": false
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Settings",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					}
				]
			},
			{
				"section": "DhcpServer",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DHCP Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			},
			{
				"section": "Administration",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					}
				]
			},
			{
				"section": "Logs",
				"userPermissions": [],
				"groupPermissions": [
					{
						"name": "Administrators",
						"canView": true,
						"canModify": true,
						"canDelete": true
					},
					{
						"name": "DHCP Administrators",
						"canView": true,
						"canModify": false,
						"canDelete": false
					},
					{
						"name": "DNS Administrators",
						"canView": true,
						"canModify": false,
						"canDelete": false
					},
					{
						"name": "Everyone",
						"canView": true,
						"canModify": false,
						"canDelete": false
					}
				]
			}
		]
	},
	"status": "ok"
}
```

### Get Permission Details

Gets details of the permissions for the specified section.

URL:\
`http://localhost:5380/api/admin/permissions/get?token=x&section=Dashboard&includeUsersAndGroups=true`

PERMISSIONS:\
Administration: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `section`: The name of the section as given in the list of permissions API call.
- `includeUsersAndGroups` (optional): Set to `true` to include a list of users and groups in the response.

RESPONSE:
```
{
	"response": {
		"section": "Dashboard",
		"userPermissions": [
			{
				"username": "shreyas",
				"canView": true,
				"canModify": false,
				"canDelete": false
			}
		],
		"groupPermissions": [
			{
				"name": "Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			{
				"name": "Everyone",
				"canView": true,
				"canModify": false,
				"canDelete": false
			}
		],
		"users": [
			"admin",
			"shreyas"
		],
		"groups": [
			"Administrators",
			"DHCP Administrators",
			"DNS Administrators",
			"Everyone"
		]
	},
	"status": "ok"
}
```

### Set Permission Details

Allows changing permissions for the specified section.

URL:\
`http://localhost:5380/api/admin/permissions/set?token=x&section=Dashboard&userPermissions=shreyas|true|false|false&groupPermissions=Administrators|true|true|true|Everyone|true|false|false`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `section`: The name of the section as given in the list of permissions API call.
- `userPermissions` (optional): A pipe `|` separated table data with each row containing username and boolean values for the view, modify and delete permissions. For example: user1|true|true|true|user2|true|false|false
- `groupPermissions` (optional): A pipe `|` separated table data with each row containing the group name and boolean values for the view, modify and delete permissions. For example: group1|true|true|true|group2|true|true|false

RESPONSE:
```
{
	"response": {
		"section": "Dashboard",
		"userPermissions": [
			{
				"username": "shreyas",
				"canView": true,
				"canModify": false,
				"canDelete": false
			}
		],
		"groupPermissions": [
			{
				"name": "Administrators",
				"canView": true,
				"canModify": true,
				"canDelete": true
			},
			{
				"name": "Everyone",
				"canView": true,
				"canModify": false,
				"canDelete": false
			}
		]
	},
	"status": "ok"
}
```

### Get Cluster state

Returns data on the current state of the Cluster.

URL:\
`http://localhost:5380/api/admin/cluster/state?token=x&includeServerIpAddresses=true`

PERMISSIONS:\
Administration: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `includeServerIpAddresses` (optional): Set to `true` to return a list of static IP addresses configured on the server. Default value is `false` when the parameter is missing.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server1.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"configLastSynced": "2025-09-26T12:30:16Z",
		"nodes": [
			{
				"id": 1342079372,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddress": "192.168.10.5",
				"type": "Secondary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			},
			{
				"id": 1653399468,
				"name": "server2.example.com",
				"url": "https://server2.example.com:53443/",
				"ipAddress": "192.168.10.101",
				"type": "Secondary",
				"state": "Unreachable",
				"lastSeen": "0001-01-01T00:00:00"
			},
			{
				"id": 1843286864,
				"name": "server3.example.com",
				"url": "https://server3.example.com:53443/",
				"ipAddress": "192.168.10.102",
				"type": "Primary",
				"state": "Connected",
				"lastSeen": "2025-09-26T12:30:16Z"
			}
		],
		"serverIpAddresses": [
			"192.168.10.5",
			"192.168.120.1",
			"192.168.180.1",
		]
	},
	"status": "ok"
}
```

### Initialize Cluster

 The initialization of a new Cluster will make the current DNS server its Primary node. You can add other DNS servers to this Cluster later which will get added as Secondary nodes. No data will be lost on this DNS server in this process. 

Note! If the web service does not have HTTPS enabled, then the initialization process will enable it automatically with a self-signed certificate. However, its recommended to manually configure HTTPS with a valid certificate before initializing the cluster.

Note! The initialization process will create two zones if they do not exist. The first zone will be the Cluster Primary zone named as the Cluster domain name specified above. The second zone will be the Cluster Catalog zone that uses 'cluster-catalog' as the subdomain name of the Cluster domain name. Use this Cluster Catalog zone for automatic provisioning of Secondary zones on all of the Cluster Secondary nodes.

Warning! The Cluster domain name cannot be changed later. Make sure that you enter the correct domain name before proceeding. 

URL:\
`http://localhost:5380/api/admin/cluster/init?token=x&clusterDomain=example.com&primaryNodeIpAddresses=192.168.10.5`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `clusterDomain`: The fully qualified domain name to be used to identify the new Cluster.
- `primaryNodeIpAddresses`: A comma separated list of IP addresses of this DNS server that will be accessible by all other DNS Servers to be added later as Secondary nodes.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server1.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"nodes": [
			{
				"id": 1081800048,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddresses": [
					"192.168.10.5"
				],
				"type": "Primary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Delete Cluster

The Delete Cluster process will remove all Cluster configuration from this Primary node. There will be no data loss except for the Cluster configuration. You will need to re-initialize the Cluster again to use clustering features on this DNS server. This call can be made only at the Primary node.
 
Note! You can delete the Cluster only when there are no Secondary nodes in the Cluster. Use the Force Delete Cluster option only when you wish this Primary node to be removed from the Cluster even when there are Secondary nodes in the Cluster. In this case, the Secondary nodes will become orphaned and you will need to promote one of them to be the new Primary node manually.  

URL:\
`http://localhost:5380/api/admin/cluster/primary/delete?token=x&forceDelete=false`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `forceDelete` (optional): Set to `true` to cause this Primary node to delete the Cluster for itself even when other Secondary nodes still exist, orphaning them. Default value is `false` when the parameter is missing.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": false,
		"dnsServerDomain": "server1",
		"version": "14.0"
	},
	"status": "ok"
}
```

### Join Cluster

This API call is used by a DNS Server instance to ask the Primary node to allow it to join the Cluster as a Secondary node. This call can be only at the Primary node.

URL:\
`http://localhost:5380/api/admin/cluster/primary/join?token=x`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `secondaryNodeId`: The Secondary node ID that was generated randomly when the server is initializing as a Secondary node.
- `secondaryNodeUrl`: The HTTPS URL of the Secondary node's API web service.
- `secondaryNodeIpAddresses`: A comma separated list of Secondary node IP addresses.
- `secondaryNodeCertificate`: The Secondary node's TLS certificate used by the API web service.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server1.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"configLastSynced": "2025-09-26T12:30:16Z",
		"nodes": [
			{
				"id": 1342079372,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddresses": [
					"192.168.10.5"
				],
				"type": "Secondary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			},
			{
				"id": 1653399468,
				"name": "server2.example.com",
				"url": "https://server2.example.com:53443/",
				"ipAddresses": [
					"192.168.10.101"
				],
				"type": "Secondary",
				"state": "Unreachable",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Remove Secondary Node

The Remove Node process will ask the selected Secondary node to leave the Cluster gracefully. The Secondary now will then initiate Leave Cluster process as if the Leave Cluster action was performed on that node itself. This call can be made only at the Primary node.

URL:\
`http://localhost:5380/api/admin/cluster/primary/removeSecondary?token=X&secondaryNodeId=811905692`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `secondaryNodeId`: The Secondary node ID which needs to be asked to leave the Cluster.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server1.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"nodes": [
			{
				"id": 1151850285,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddresses": [
					"192.168.10.5"
				],
				"type": "Primary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Delete Secondary Node

The Delete Node process will immediately delete the selected Secondary node entry from the Cluster without asking the node to leave graceful. This call can be made only at the Primary node.

URL:\
`http://localhost:5380/api/admin/cluster/primary/deleteSecondary?token=X&secondaryNodeId=811905692`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `secondaryNodeId`: The Secondary node ID which must be deleted from the Cluster immediately.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server1.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"nodes": [
			{
				"id": 1151850285,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddresses": [
					"192.168.10.5"
				],
				"type": "Primary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Update Secondary Node

The Update Secondary Node call is used by the Secondary node to update its details like URL, IP Address and TLS certificate on the Primary node. This call can be made only at the Primary node.

URL:\
`http://localhost:5380/api/admin/cluster/primary/updateSecondary?token=x&secondaryNodeId=811905692&secondaryNodeUrl=https%3A%2F%2Fserver2.example.com%3A53443%2F&secondaryNodeIpAddresses=192.168.10.101&secondaryNodeCertificate=<base64url>`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `secondaryNodeId`: The Secondary node ID that identifies the node.
- `secondaryNodeUrl`: The HTTPS API web service URL of the Secondary node to be updated.
- `secondaryNodeIpAddresses`: A comma separated list of IP addresses of the Secondary node to be updated.
- `secondaryNodeCertificate`: The web service TLS certificate encoded in Base64 URL format.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server1.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"configLastSynced": "2025-09-26T12:30:16Z",
		"nodes": [
			{
				"id": 1342079372,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddresses": [
					"192.168.10.5"
				],
				"type": "Secondary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			},
			{
				"id": 1653399468,
				"name": "server2.example.com",
				"url": "https://server2.example.com:53443/",
				"ipAddresses": [
					"192.168.10.101"
				],
				"type": "Secondary",
				"state": "Connected",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Transfer Config

The Transfer Config call is used by Secondary nodes to  sync the complete config data from the Primary node. This call can be made only at the Primary node.

URL:\
`http://localhost:5380/api/admin/cluster/primary/transferConfig?token=x&includeZones=`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `includeZones` (optional): A list of comma separated domain names of the zones that should be included to transfer DNSSEC private keys.

RESPONSE HEADERS:\
- `If-Modified-Since` (optional): The date time stamp of the last config transfer so as to allow transferring only changes done after the specified date time. The format is the standard HTTP header format for `If-Modified-Since`.

RESPONSE: A zip file with content type `application/zip` and content disposition set to `attachment`.

### Set Cluster Options

Allows setting Cluster options to be used by all Secondary nodes. This call can be made only at the Primary node.

URL:\
`http://localhost:5380/api/admin/cluster/primary/setOptions?token=x`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `heartbeatRefreshIntervalSeconds` (optional): The interval in seconds in which the DNS server must refresh the state of all nodes in the Cluster. The valid range is `10`-`300` and default value is `30`.
- `heartbeatRetryIntervalSeconds` (optional): The interval in seconds in which the DNS server must retry the state refresh process for all nodes in case of a failure. The valid range is `10`-`300` and default value is `10`.
- `configRefreshIntervalSeconds` (optional): The interval in seconds in which the DNS server must refresh the configuration from the Primary node. The valid range is `30`-`3600` and default value is `900`.
- `configRetryIntervalSeconds` (optional): The interval in seconds in which the DNS server must retry the configuration refresh process for the Primary node in case of a failure. The valid range is `30`-`3600` and default value is `60`.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server1.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"configLastSynced": "2025-09-26T12:30:16Z",
		"nodes": [
			{
				"id": 1342079372,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddresses": [
					"192.168.10.5"
				],
				"type": "Secondary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			},
			{
				"id": 1653399468,
				"name": "server2.example.com",
				"url": "https://server2.example.com:53443/",
				"ipAddresses": [
					"192.168.10.101"
				],
				"type": "Secondary",
				"state": "Connected",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Initialize And Join Cluster

Joining a Cluster will make this DNS server its Secondary node. This process will overwrite configuration on this DNS server for Allowed, Blocked, Apps, Settings and Administration sections. The DNS server will automatically synchronize its configuration with the Primary node in the Cluster. This call can be only at the Secondary node.
 
Note! The process to join the Cluster may take a while to complete depending on the amount of initial config data that needs to be synchronized from the Primary node. Please be patient till the process completes.

Note! If the web service does not have HTTPS enabled, then the joining process will enable it automatically with a self-signed certificate. However, its recommended to manually configure HTTPS with a valid certificate before joining the cluster.

Warning! Joining a Cluster will cause configuration on this DNS server to be overwritten permanently for Allowed, Blocked, Apps, Settings and Administration sections! 

URL:\
`http://server2.home:5380/api/admin/cluster/initJoin?token=x&secondaryNodeIpAddresses=192.168.10.101&primaryNodeUrl=https%3A%2F%2Fserver1.example.com%3A53443%2F&primaryNodeIpAddress=192.168.10.5&ignoreCertificateErrors=true&primaryNodeUsername=admin&primaryNodePassword=admin&primaryNodeTotp=`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `secondaryNodeIpAddresses`: A comma separated list of IP addresses of this DNS server that will be accessible by all other DNS Server nodes in the Cluster.
- `primaryNodeUrl`: The web service HTTPS URL of the Primary node in the Cluster.
- `primaryNodeIpAddress` (optional): The IP address of the Primary node in the Cluster. When unspecified, domain name in the Primary node URL will be resolved and used.
- `ignoreCertificateErrors` (optional): Set to `true` only when you know that the Primary node web service is using a self-signed TLS certificate and is reachable on a private network. 
- `primaryNodeUsername`: The username of an administrator on the Primary node in the Cluster.
- `primaryNodePassword`: The password of the administrator user specified above.
- `primaryNodeTotp` (optional): The the 6-digit code you see in your authenticator app for the administrator user specified above. Only to be used if the user has 2FA enabled.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server2.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"configLastSynced": "2025-09-27T13:19:55Z",
		"nodes": [
			{
				"id": 1151850285,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddresses": [
					"192.168.10.5"
				],
				"type": "Primary",
				"state": "Connected",
				"lastSeen": "2025-09-27T13:19:54.6215569Z"
			},
			{
				"id": 811905692,
				"name": "server2.example.com",
				"url": "https://server2.example.com:53443/",
				"ipAddresses": [
					"192.168.10.101"
				],
				"type": "Secondary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Leave Cluster

The Leave Cluster process will remove all Cluster configuration from this Secondary node and leave the Cluster gracefully. There will be no data loss except for the Cluster configuration. You will need to re-join the Cluster again to use this DNS server as a Secondary node. This call can be made only at the Secondary node.
 
Note! Use the Force Leave Cluster option only when the Primary node is unreachable/decommissioned and thus cannot leave the Cluster gracefully. 

URL:\
`http://localhost:5380/api/admin/cluster/secondary/leave?token=x`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `forceLeave` (optional): Set to `true` to make this Secondary node to leave the Cluster without informing the Primary node.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": false,
		"dnsServerDomain": "server2",
		"version": "14.0"
	},
	"status": "ok"
}
```

### Notify

The Notify call is made by the Primary node to all Secondary nodes in the Cluster whenever there is any change in the configuration that the Secondary zones must sync to. The Secondary nodes have to use the Transfer Config call to sync the config changes when this notification is received. The Notify call also includes the latest details of the Primary node that must be updated and used. This call can be made only at the Secondary node.

URL:\
`http://localhost:5380/api/admin/cluster/secondary/notify?token=x`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `primaryNodeId`: The calling Primary node's ID to allow identification at the Secondary node.
- `primaryNodeUrl`: The calling Primary node's API web service URL.
- `primaryNodeIpAddresses`: A comma separated list of the calling Primary node's IP addresses.

RESPONSE:
```
{
	"status": "ok"
}
```

### Resync Cluster

The Resync cluster call allows an admin user to manually trigger a complete configuration resync on the Secondary node. When triggered, the Secondary node will use the Transfer Config call to sync the complete configuration from the Primary node. This call can be made only at the Secondary node.

URL:\
`http://localhost:5380/api/admin/cluster/secondary/resync?token=x`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"status": "ok"
}
```

### Update Primary Node

Allows updating the Primary node details like the API URL and IP address on the Secondary node. This call is useful when the Primary node's IP address or URL has changed while the Secondary node was offline causing it to have old details of the Primary node. This call can be made only at the Secondary node.

URL:\
`http://localhost:5380/api/admin/cluster/secondary/updatePrimary?token=x`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `primaryNodeUrl`: The web service HTTPS URL of the Primary node in the Cluster.
- `primaryNodeIpAddresses` (optional): The IP address of the Primary node in the Cluster. When unspecified, domain name in the Primary node URL will be resolved and used.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server2.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"configLastSynced": "2025-09-27T13:19:55Z",
		"nodes": [
			{
				"id": 1151850285,
				"name": "server1.example.com",
				"url": "https://server1.example.com:53443/",
				"ipAddresses": [
					"192.168.10.5"
				],
				"type": "Primary",
				"state": "Connected",
				"lastSeen": "2025-09-27T13:19:54.6215569Z"
			},
			{
				"id": 811905692,
				"name": "server2.example.com",
				"url": "https://server2.example.com:53443/",
				"ipAddresses": [
					"192.168.10.101"
				],
				"type": "Secondary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Promote To Primary

The promote To Primary node process will resync complete configuration from the Primary node and then proceed to delete it from the Cluster followed by upgrading the selected Secondary node to become the Primary node in the Cluster. The former Primary node when deleted will cause it to delete all its own Cluster configuration leaving the Cluster without causing any other data loss. This call can be made only at the Secondary node.

Note! Use the Force Delete Current Primary Node option only when the Primary node is unreachable/decommissioned and thus cannot be deleted from the Cluster gracefully.

Note! The process to promote to Primary node may take a while to complete depending on the size of the complete configuration being resynced and the number of local zones that need to be converted. Please be patient till the process completes.

URL:\
`http://localhost:5380/api/admin/cluster/secondary/promote?token=x`

PERMISSIONS:\
Administration: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `forceDeletePrimary` (optional): Set to `true` for the current Primary node to be deleted from the Cluster without resyncing complete configuration from it and without inform it.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server2.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"configLastSynced": "2025-09-27T13:19:55Z",
		"nodes": [
			{
				"id": 811905692,
				"name": "server2.example.com",
				"url": "https://server2.example.com:53443/",
				"ipAddresses": [
					"192.168.10.101"
				],
				"type": "Primary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

### Update Node IP Addresses

Allows to update the current Cluster node's IP address. This call can be made at both the Primary and Secondary nodes.

URL:\
`http://localhost:5380/api/admin/cluster/updateIpAddresses?token=x`

PERMISSIONS:\
Administration: Modify

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `ipAddresses`: A comma separated list of IP addresses to be updated for the current node.

RESPONSE:
```
{
	"response": {
		"clusterInitialized": true,
		"dnsServerDomain": "server2.example.com",
		"version": "14.0",
		"clusterDomain": "example.com",
		"heartbeatRefreshIntervalSeconds": 30,
		"heartbeatRetryIntervalSeconds": 10,
		"configRefreshIntervalSeconds": 900,
		"configRetryIntervalSeconds": 60,
		"configLastSynced": "2025-09-27T13:19:55Z",
		"nodes": [
			{
				"id": 811905692,
				"name": "server2.example.com",
				"url": "https://server2.example.com:53443/",
				"ipAddresses": [
					"192.168.10.101"
				],
				"type": "Primary",
				"state": "Self",
				"lastSeen": "0001-01-01T00:00:00"
			}
		]
	},
	"status": "ok"
}
```

## Log API Calls

### List Logs

Lists all logs files available on the DNS server.

URL:\
`http://localhost:5380/api/logs/list?token=x`

OBSOLETE PATH:\
`/api/listLogs`

PERMISSIONS:\
Logs: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {
		"logFiles": [
			{
				"fileName": "2020-09-19",
				"size": "8.14 KB"
			},
			{
				"fileName": "2020-09-15",
				"size": "5.6 KB"
			},
			{
				"fileName": "2020-09-12",
				"size": "18.4 KB"
			},
			{
				"fileName": "2020-09-11",
				"size": "1.78 KB"
			},
			{
				"fileName": "2020-09-10",
				"size": "2.03 KB"
			}
		]
	},
	"status": "ok"
}
```

### Download Log

Downloads the log file.

URL:\
`http://localhost:5380/api/logs/download?token=x&fileName=2020-09-10&limit=2`

OBSOLETE PATH:\
`/log/{fileName}`

PERMISSIONS:\
Logs: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `fileName`: The `fileName` returned by the List Logs API call.
- `limit` (optional): The limit of number of mega bytes to download the log file. Default value is `0` when parameter is missing which indicates there is no limit.

RESPONSE:
Response is a downloadable file with `Content-Type: text/plain` and `Content-Disposition: attachment;filename=name`

### Delete Log

Permanently deletes a log file from the disk.

URL: 
`http://localhost:5380/api/logs/delete?token=x&log=2020-09-19`

OBSOLETE PATH:\
`/api/deleteLog`

PERMISSIONS:\
Logs: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `log`: The `fileName` returned by the List Logs API call.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Delete All Logs

Permanently delete all log files from the disk.

URL:\
`http://localhost:5380/api/logs/deleteAll?token=x`

OBSOLETE PATH:\
`/api/deleteAllLogs`

PERMISSIONS:\
Logs: Delete

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.

RESPONSE:
```
{
	"response": {},
	"status": "ok"
}
```

### Query Logs

Queries for logs to a specified DNS app.

URL:\
`http://localhost:5380/api/logs/query?token=x&name=AppName&classPath=AppClassPath&=pageNumber=1&entriesPerPage=10&descendingOrder=true&start=yyyy-MM-dd HH:mm:ss&end=yyyy-MM-dd HH:mm:ss&clientIpAddress=&protocol=&responseType=&rcode=&qname=&qtype=&qclass=`

OBSOLETE PATH:\
`/api/queryLogs`

PERMISSIONS:\
Logs: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `name`: The name of the installed DNS app.
- `classPath`: The class path of the DNS app.
- `pageNumber` (optional): The page number of the data set to retrieve.
- `entriesPerPage` (optional): The number of entries per page.
- `descendingOrder` (optional): Orders the selected data set in descending order.
- `start` (optional): The start date time in ISO 8601 format to filter the logs.
- `end` (optional): The end date time in ISO 8601 format to filter the logs.
- `clientIpAddress` (optional): The client IP address to filter the logs.
- `protocol` (optional): The DNS transport protocol to filter the logs. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`].
- `responseType` (optional): The DNS server response type to filter the logs. Valid values are [`Authoritative`, `Recursive`, `Cached`, `Blocked`, `UpstreamBlocked`, `CacheBlocked`].
- `rcode` (optional): The DNS response code to filter the logs.
- `qname` (optional): The query name (QNAME) in the request question section to filter the logs.
- `qtype` (optional): The DNS resource record type (QTYPE) in the request question section to filter the logs.
- `qclass` (optional): The DNS class (QCLASS) in the request question section to filter the logs.

RESPONSE:
```
{
	"response": {
		"pageNumber": 1,
		"totalPages": 2,
		"totalEntries": 13,
		"entries": [
			{
				"rowNumber": 1,
				"timestamp": "2021-09-10T12:22:52Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Recursive",
				"responseRtt": 33.45,
				"rcode": "NoError",
				"qname": "google.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": "172.217.166.46"
			},
			{
				"rowNumber": 2,
				"timestamp": "2021-09-10T12:37:02Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 3,
				"timestamp": "2021-09-11T09:13:31Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Authoritative",
				"rcode": "ServerFailure",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 4,
				"timestamp": "2021-09-11T09:14:48Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Authoritative",
				"rcode": "ServerFailure",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 5,
				"timestamp": "2021-09-11T09:27:25Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 6,
				"timestamp": "2021-09-11T09:27:29Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "www.example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 7,
				"timestamp": "2021-09-11T09:28:36Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "www.example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 8,
				"timestamp": "2021-09-11T09:28:41Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 9,
				"timestamp": "2021-09-11T09:28:44Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Blocked",
				"rcode": "NxDomain",
				"qname": "sdfsdf.example.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": ""
			},
			{
				"rowNumber": 10,
				"timestamp": "2021-09-11T09:42:02Z",
				"clientIpAddress": "127.0.0.1",
				"protocol": "Udp",
				"responseType": "Recursive",
				"responseRtt": 23.63,
				"rcode": "NoError",
				"qname": "technitium.com",
				"qtype": "A",
				"qclass": "IN",
				"answer": "139.59.3.235"
			}
		]
	},
	"status": "ok"
}
```

### Export Query Logs

Queries for logs to a specified DNS app and exports the data as a CSV file.

URL:\
`http://localhost:5380/api/logs/export?token=x&name=AppName&classPath=AppClassPath&start=yyyy-MM-dd HH:mm:ss&end=yyyy-MM-dd HH:mm:ss&clientIpAddress=&protocol=&responseType=&rcode=&qname=&qtype=&qclass=`

PERMISSIONS:\
Logs: View

WHERE:
- `token`: The session token generated by the `login` or the `createToken` call.
- `node` (optional): The node domain name for which the this API call is intended. When unspecified, the current node is used. This parameter can be used only when Clustering is initialized.
- `name`: The name of the installed DNS app.
- `classPath`: The class path of the DNS app.
- `start` (optional): The start date time in ISO 8601 format to filter the logs.
- `end` (optional): The end date time in ISO 8601 format to filter the logs.
- `clientIpAddress` (optional): The client IP address to filter the logs.
- `protocol` (optional): The DNS transport protocol to filter the logs. Valid values are [`Udp`, `Tcp`, `Tls`, `Https`, `Quic`].
- `responseType` (optional): The DNS server response type to filter the logs. Valid values are [`Authoritative`, `Recursive`, `Cached`, `Blocked`, `UpstreamBlocked`, `CacheBlocked`].
- `rcode` (optional): The DNS response code to filter the logs.
- `qname` (optional): The query name (QNAME) in the request question section to filter the logs.
- `qtype` (optional): The DNS resource record type (QTYPE) in the request question section to filter the logs.
- `qclass` (optional): The DNS class (QCLASS) in the request question section to filter the logs.

RESPONSE: Response is a downloadable text file with `Content-Type: text/csv` and `Content-Disposition: attachment` headers set.
