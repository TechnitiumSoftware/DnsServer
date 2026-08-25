READ ME
=======

This folder contains JSON formatted files that are used by the web app to fetch various lists. The JSON files that end with "-builtin" are the ones that are shipped as a part of the software package and are expected to be overwritten when you update the software.

You can override these built-in lists by creating your own custom lists. To do this, create a new JSON file with the exact same name except, replace "-builtin" with "-custom" in the name. Use the same JSON format as the built-in list in your custom list to add items. When a custom list is available, the web app will always prefer it.

For example, if you wish to have a custom list of servers listed for DNS Client, copy the "dnsclient-server-list-builtin.json" file as "dnsclient-server-list-custom.json" and edit it to have the desired list of servers.

Note! Once the custom list file is saved, you will need to refresh the web app so that it loads the updated custom list.

Warning! Editing the built-in json files will make it look like it works well, but when the software is updated, the built-in json file will be overwritten causing you to lose any custom changes that you made.
