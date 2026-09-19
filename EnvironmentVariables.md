# Technitium DNS Server Environment Variables

Technitium DNS Server supports the following environment variables that are used to configure DNS server such that the values are always read directly from the configured environment variables. Unlike Docker Environment Variables, these ones are not used to initialize the DNS Server's config files. 

Note! Any changes made to these variables require restarting the DNS Server to apply them.

The environment variables are described below:

| Environment Variable                              | Type    | Description                                                                                                                              |
| ------------------------------------------------- | ------- | -----------------------------------------------------------------------------------------------------------------------------------------|
| DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH            | String  | The path to the folder to be used as the DNS Web Service's www root folder. The default www folder path is used when this variable is not set or when the configured folder path does not exist. |
| DNS_SERVER_AUTH_STATIC_SESSIONS                   | String  | Allows configuring predefined static API sessions via environment variables which are not visible via the API. The string value must be a comma separated list of entries where each entry is a colon separated key value pair. An entry contains a username and its corresponding token in `<username>:<token>` format. The token must be unique per entry and must be a hex string of exactly 64 bytes length. For example, `admin:bc847a5fdf2d67267a1d607e053a150e63c4e4837ea9272169a2c739556ccf35,user:dbee4e3fd45f5e4d766718533bc264aab0970e5a4ba13cbccca5fe5d3c9cec36`.
