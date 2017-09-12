# NexposeCLI.rb


    Usage: certificationScan.rb [--username user] [--password secret] [--ip 10.0.1.1]
    Usage: certificationScan.rb [--username user] [--password secret] [--input-list /path/to/file.txt]
    Usage: certificationScan.rb [--username user] [--password secret] [--site-list]
    Usage: certificationScan.rb [--username user] [--password secret] [--engine-list]

    -u, --username <username>        Nexpose user name.
    -p, --password <password>        Nexpose password.
    -e, --engine <ID>                Enginge ID that will run the scan. Default is the console.
    -i, --ip <address>               Single IP address of system to scan.
    -I, --input-list <path>          Path to file containing one ip per line.
    -c, --credentials <uname,pw>     Windows credentials used for authenticated scanning. Format: username,password
    -s, --site <ID>                  Site ID that will be used for scanning. If one is not provided a temporary site will be created
    -C, --console <url>              Nexopse console host name or IP address. 127.0.0.1 is the default if this option is not used.
    -E, --engine-list                List available scan engine ID's and names
    -S, --site-list                  List available site ID's and names
    -r, --remove-assets              Remove assets currently in site. All assets in the site will be scanned unless they are removed
    -h, --help                       Display this help message
