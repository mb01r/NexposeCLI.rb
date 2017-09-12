#!/bin/env ruby
# Written by Christos Mamas
# User must use Nexpose credentials
# Uing either a single IP or a file containing one IP per line.
# Once the scan has completed an asset PDF report will be created.

############################### Required Modules ################################
require 'highline/import'
require 'nexpose'
include Nexpose
require 'optparse'
require 'colorize'


################################ Variables ######################################
$time = Time.new
$time = $time.strftime("%Y%m%d%H%M%S")
$pdf = "VulnerabilityReport-#{$time}.pdf"
$list = Array.new
$options = {:username => nil, :password => nil, :ip => nil, :ip_list => nil, :site => nil, :engine => 1, :console => nil, :engine_list => nil, :site_list => nil, :name => nil, :creds => nil, :remove_assets => nil}

############################### Argument Parser #################################
parser = OptionParser.new do |opts|
	opts.banner = "\nUsage: certificationScan.rb [--username user] [--password secret] [--ip 10.0.1.1]\nUsage: certificationScan.rb [--username user] [--password secret] [--input-list /path/to/file.txt]\nUsage: certificationScan.rb [--username user] [--password secret] [--site-list]\nUsage: certificationScan.rb [--username user] [--password secret] [--engine-list]\n\n"

	opts.on('-u', '--username <username>', 'Nexpose user name.') do |username|
		$options[:username] = username
	end
	opts.on('-p', '--password <password>', 'Nexpose password.') do |pass|
		$options[:password] = pass
	end
	opts.on('-e', '--engine <ID>', Float, 'Enginge ID that will run the scan. Default is the console.') do |engine|
		$options[:engine] = engine
	end
	opts.on('-i', '--ip <address>', 'Single IP address of system to scan.') do |ip|
		$options[:ip] = ip
	end
	opts.on('-I', '--input-list <path>', 'Path to file containing one ip per line.') do |ip|
		$options[:ip_list] = ip
	end
	opts.on('-c', '--credentials <uname,pw>', 'Windows credentials used for authenticated scanning. ' + 'Format: username,password'.green) do |creds|
		$options[:creds] = creds
	end
	opts.on('-s', '--site <ID>', Float, 'Site ID that will be used for scanning. If one is not provided a temporary site will be created') do |site|
		$options[:site] = site
	end
	opts.on('-C', '--console <url>', 'Nexopse console host name or IP address. 127.0.0.1 is the default if this option is not used.') do |console|
		$options[:console] = console
	end
	opts.on('-E', '--engine-list', "List available scan engine ID's and names") do 
		$options[:engine_list] = true
	end
	opts.on('-S', '--site-list', "List available site ID's and names") do
		$options[:site_list] = true
	end
	opts.on('-r', '--remove-assets', 'Remove assets currently in site. All assets in the site will be scanned unless they are removed') do 
		$options[:remove_assets] = true
	end
	opts.on('-h', '--help', 'Display this help message') do
                # Leave this empty or multiple opts lists will print.
        end
end

begin
	parser.parse!
rescue Exception => e
	puts "[-] Error in options. use --help for currect syntax.".red
	abort
end

######################################## Functions ########################################
def ipcheck(address)

	if /^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.match(address)
		puts "[-] Private IP space is not a valid target.".red
		exit(1)
	elsif /^169\.254\.[0-9]{1,3}\.[0-9]{1,3}$/.match(address)
		puts "[-] APIPA address space is not a valid target.".red
		exit(1)
        elsif /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/.match(address)
                return address
        else
                puts "[-] #{address.chomp} is not a valid IP address.".red
                exit(1)
        end
end

def login()

	begin
        # Verify usename input
        if $options[:username] == nil then
            $options[:username] = ask("Enter User Name: ".light_blue)
        end
        
        # Verify password has been input
        if $options[:password] == nil then
            $options[:password] = ask("Enter Password: ".light_blue) {|q| q.echo = ""}
        end

		@nsc = Nexpose::Connection.new($options[:console], $options[:username], $options[:password])
        	@nsc.login
        	at_exit {@nsc.logout} # puts "[+] Logged out.".green}

	rescue Exception => e
        	puts "[-] Authentication failure. Please try again.".red
		abort
	end
end

def scanAndReport()

        puts "[+] Starting scan.".green
        scan = $site.scan(@nsc)

        begin
                sleep(60)
                status = @nsc.scan_status(scan.id)
                puts "[+] Scan status: #{status.to_s}".yellow
        end while status == Nexpose::Scan::Status::RUNNING or status == Nexpose::Scan::Status::INTEGRATING

        if status == Nexpose::Scan::Status::ABORTED
                puts "[+] Scan status: #{status.to_s}! Contact your administrator.".red
                exit(1)
        elsif status == Nexpose::Scan::Status::STOPPED
                puts "[+] Scan status: #{status.to_s}! Contact your administrator.".red
                exit(1)
        elsif status == Nexpose::Scan::Status::ERROR
                puts "[+] Scan status: #{status.to_s}! Contact your administrator.".red
                exit(1)
        elsif status == Nexpose::Scan::Status::PAUSED
                puts "[+] Scan status: #{status.to_s}! Contact your administrator.".red
                exit(1)
        elsif status == Nexpose::Scan::Status::UNKNOWN
                puts "[+] Scan status: #{status.to_s}! Contact your administrator.".red
                exit(1)
        else status == Nexpose::Scan::Status::FINISHED
                puts "[+] Generating Report.".green

                report = Nexpose::AdhocReportConfig.new('asset-report', 'pdf', $site.id)

                #fh = File.open("#{ENV['HOME']}/Documents/#{$pdf}", "a+")
                fh = File.open("#{ENV['HOME']}/#{$pdf}", "wb")
                fh.write(report.generate(@nsc))
                fh.close
                puts "[+] #{$pdf} has been created.".green
                puts "[+] The report can be found in '#{ENV['HOME']}'".green
        end

end

def scanList(assetList)
	fh = File.open(assetList, "r")
	fh.each do |ip|
		$list.push(ipcheck(ip.strip))
	end
        puts "[+] IP addresses are properly formated.".green
	
	if $options[:site] == nil then
		$site = Nexpose::Site.new("Temp_site_#{$time}",'full-audit-_-sungard')
	else
		begin
			$site = Nexpose::Site.load($nsc, $options[:site]) #.to_i)
		rescue Exception => e
			puts "[-] Site ID is not valid.".red
			exit(1)
		end
	end
        
	$list.each do |ip|
		$site.include_asset(ip)
	end

	# Set the scan engine used for scanning. 
	# If the site is new the local console will be used for scanning.
	# If the site has been previously used the last scan engine used will be used for the current scan.
	unless $options[:engine] == nil then
		begin
			$site.engine_id = $options[:engine]
			puts "[+] Scanning with engine ID: #{$options[:engine].to_i}.".green
		rescue NexposeAPI => e #Exception => e # StandardError
			puts "[-] Scan engine ID is not valid.".red
			exit(1)
			abort
		end
	end

	begin
		if $options[:remove_assets] == true then
	                $site.included_addresses.each do |asset|
        	                unless $list[0].include?(asset.from) then
                	                $site.remove_included_asset(asset.from)
	                        end
	                end
		end
        rescue Nexpose::PermissionError => e
                puts "[-] Permission Denied.".red
        end

        $site.save(@nsc)
        scanAndReport()
	
	$list.each do |ip|
		$site.remove_included_asset(ip)
	end
 
	if $options[:site] == nil then
		$site.delete(@nsc)
		$creds.delete(@nsc)
	        exit(0)
	end

end
	
def scanAsset(ip)
        $list.push(ipcheck(ip))
        puts "[+] IP address is properly formated.".green

	if $options[:site] == nil then
		$site = Nexpose::Site.new("Temp_site_#{$time}",'full-audit-_-sungard')
	else
		$site = Nexpose::Site.load(@nsc, $options[:site].to_i)
	end
        
	$site.include_asset($list[0])

	# Set the scan engine used for scanning. 
	# If the site is new the local console will be used for scanning.
	# If the site has been previously used the last scan engine used will be used for the current scan.
	unless $options[:engine] == nil then
		begin
			$site.engine_id = $options[:engine]
			puts "[+] Scanning with engine ID: #{$options[:engine].to_i}.".green
		rescue NoMethodError => e
			puts "[-] Scan engine ID is not valid.".red
			exit(1)
		end
	end

	begin
		if $options[:remove_assets] then
			$site.included_addresses.each do |asset|
				unless $list[0].include?(asset.from) then
					$site.remove_included_asset(asset.from)
				end
			end
		end
	rescue Nexpose::PermissionError => e
		puts "[-] Permission Denied.".red
	end

        $site.save(@nsc)
        scanAndReport()

	if $options[:site] == nil then
		$site.delete(@nsc)
		$creds.delete(@nsc)
        	exit(0)
	end
end

def listEngines()
	@nsc.list_engines.each do |engine|
		puts "ID: ".green + "#{engine.id}\t" + "Name: ".green + "#{engine.name}"
	end
end

def listSites()
	@nsc.list_sites.each do |site|
		puts "ID: ".green + "#{site.id}\t" + "Name: ".green + "#{site.name}"
	end
end

def addCreds(username, password)
	begin
		$creds = Nexpose::SharedCredential.new("Certification credentials #{username}")
		$creds.service = Credential::Service::CIFS
		$creds.privilege_username = username
		$creds.privilege_password = password
		$creds.sites << $site.id
		$creds.save(@nsc)

		# At this point the new creds id is -1 so we can't delete it. 
		# We need to find the newly created credential in the connection
		# and add that ID to the $creds variable.
		@nsc.shared_credentials.each do |cred|
			if cred.name == $creds.name then 
				$creds.id = cred.id 
			end
		end	
	rescue Exception => e
		puts "[-] Credentials failed to load.".red
	end		
end

########################################## Main #########################################################

# User must set --ip, --input-list, --engine-list, or --site-list to use the script.
if $options[:ip] == nil and $options[:ip_list] == nil and $options[:engine_list] == nil and $options[:site_list] == nil then
	puts parser.display
	exit(1)
end

# User cannot use --ip or --input-list with --engine-list or --site-list.
if ($options[:ip] != nil or $options[:ip_list] != nil) and ($options[:engine_list] != nil or $options[:site_list] != nil) then
	puts "[-] List options and scan options are not valid together".red
	exit(1)
end
 
# User can not use --ip and --input-list.
if $options[:ip] != nil and $options[:ip_list] != nil then
	puts "[-] Scanning a single IP and a list of IP addresses are not valid options together.".red
	exit(1)
end

# User can not use --engine-list and --site-list together.
if $options[:engine_list] == true and $options[:site_list] == true then
	puts "[-] Listing engines and sites together is not valied.".red
	exit(1)
end 

# List available engines when -E or --engine-list switchs are used.
if $options[:engine_list] != nil then
    login()
	listEngines()	
	exit(0)
end

# Set the console connection to local host if the --console switch is not used.
if $options[:console] == nil then
	$options[:console] = '127.0.0.1'
	puts "[+] Local host will be used for console connection.".yellow
end

# List available sites when -S or --site-list switches are used.
if $options[:site_list] == true then
    login()
	listSites()
	exit(0)
end

# Scan single IP address.
if $options[:ip] != nil then
    login()

	unless $options[:creds] == nil then
		addCreds($options[:creds].split(",")[0], $options[:creds].split(",")[1])
	end
	
	begin
		scanAsset($options[:ip])
	rescue Nexpose::PermissionError => e
		puts "[-] You do not have to preform this action".red
	end
end

# Scan text file containing IP addresses.
if $options[:ip_list] != nil then
    login()

	unless $options[:creds] == nil then
		addCreds($options[:creds].split(",")[0], $options[:creds].split(",")[1])
	end

	scanList($options[:ip_list])
end
