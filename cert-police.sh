#!/bin/bash
#title: certpolice.sh
#description:   Certificate Transparency Monitoring
#author:        mr-rizwan-syed | @_r12w4n
#version:       1.0.0
#==============================================================================

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
MAGENTA=`tput setaf 5`
BLUE=`tput setaf 4`
NC=`tput sgr0`

function cleanup() {
  echo -e "\n${YELLOW}[INFO]${NC} Received interrupt signal. Cleaning up before exit..."
  echo -e "${BLUE}[INFO]${NC} Unresolved subdomains saved to: $output_file"
  echo -e "${BLUE}[INFO]${NC} Resolved subdomains saved to: $resolved_file"
  exit 0
}

# Enhanced signal handling
trap cleanup SIGINT SIGTERM

check_exist() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    elif [ -d "$1" ] || [ -e "$1" ]; then
        return 0
    else
        return 1
    fi
}

dependency_installer(){
    if ! check_exist pv; then
        apt-get install -y pv &>/dev/null
    fi
    if ! check_exist anew; then
        echo "${YELLOW}[*] Installing anew ${NC}"
        go install github.com/tomnomnom/anew@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: anew" >/dev/null
    fi
    if ! check_exist python3; then
        echo "${YELLOW}[*] Installing python3 ${NC}"
        apt install python3 -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: python3" >/dev/null
    fi
    if ! check_exist pip; then
        echo "${YELLOW}[*] Installing python3-pip ${NC}"
        apt install python3-pip -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: python3-pip" >/dev/null
    fi
    if ! check_exist jq; then
        echo "${YELLOW}[*] Installing jq ${NC}"
        apt install jq -y 2>/dev/null | pv -p -t -e -N "Installing Tool: jq" >/dev/null
    fi
    if ! check_exist nslookup; then
        echo "${YELLOW}[*] Installing dnsutils ${NC}"
        apt install dnsutils -y 2>/dev/null | pv -p -t -e -N "Installing Tool: dnsutils" >/dev/null
    fi
    if ! check_exist certstream; then
        echo "${YELLOW}[*] Installing certstream ${NC}"
	pip install certstream --break-system-packages 2>/dev/null | pv -p -t -e -N "Installing Tool: certstream" >/dev/null
    fi
    if ! check_exist notify; then
        echo "${YELLOW}[*] Installing notify ${NC}"
        go install -v github.com/projectdiscovery/notify/cmd/notify@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Notify" >/dev/null
    fi
    if ! check_exist tlsx; then
        echo "${YELLOW}[*] Installing tlsx ${NC}"
        go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: TLSx" >/dev/null
    fi
    if ! check_exist nuclei; then
        echo "${YELLOW}[*] Installing nuclei ${NC}"
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Nuclei" >/dev/null
    fi
    if ! check_exist naabu; then
        echo "${YELLOW}[*] Installing naabu ${NC}"
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Naabu" >/dev/null
    fi
    if ! check_exist arjun; then
        echo "${YELLOW}[*] Installing arjun ${NC}"
        pipx install arjun --break-system-packages 2>/dev/null | pv -p -t -e -N "Installing Tool: Arjun" >/dev/null
    fi
    if ! check_exist httpx; then
        echo "${YELLOW}[*] Installing httpx ${NC}"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Httpx" >/dev/null
    fi
    if ! check_exist dirsearch; then
        echo "${YELLOW}[*] Installing dirsearch ${NC}"
        pip install dirsearch --break-system-packages 2>/dev/null | pv -p -t -e -N "Installing Tool: Dirsearch" >/dev/null
    fi
    if ! check_exist gau; then
        echo "${YELLOW}[*] Installing gau ${NC}"
        go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Gau" >/dev/null
    fi
    if ! check_exist katana; then
        echo "${YELLOW}[*] Installing katana ${NC}"
        go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Katana" >/dev/null
    fi

}

required_tools=("pv" "anew" "python3" "pip" "jq" "nslookup" "certstream" "notify" "tlsx" "nuclei" "naabu" "arjun" "httpx" "dirsearch" "gau" "katana")

missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! check_exist "$tool"; then
        missing_tools+=("$tool")
        echo "Dependency ${RED}$tool${NC} not found..."
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e ""
    echo -e "${RED}[-]The following tools are not installed:${NC} ${missing_tools[*]}"
    dependency_installer
    exit 1
fi

banner(){
echo -e '
 â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•—     â–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—
â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â•šâ•â•â–ˆâ–ˆâ•”â•â•â•   â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â•â•â•â•
â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  
â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•”â•â•â•  â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—   â–ˆâ–ˆâ•‘â•šâ•â•â•â•â•â–ˆâ–ˆâ•”â•â•â•â• â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•”â•â•â•  
â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘      â–ˆâ–ˆâ•‘     â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—
 â•šâ•â•â•â•â•â•â•šâ•â•â•â•â•â•â•â•šâ•â•  â•šâ•â•   â•šâ•â•      â•šâ•â•      â•šâ•â•â•â•â•â• â•šâ•â•â•â•â•â•â•â•šâ•â• â•šâ•â•â•â•â•â•â•šâ•â•â•â•â•â•â•'
echo -e "Certificate Transparency Monitoring @_r12w4n"
echo -e
}

# Initialize variables
silent=false
notify=false
nuclei_scan=false
naabu_scan=false
arjun_scan=false
dirsearch_scan=false
url_exposure_scan=false
targets=()  # Global array for target domains and keywords
POSITIONAL_ARGS=()  # Array to store positional arguments

# Function to check if a domain resolves
check_dns_resolution() {
    local domain="$1"
    
    # Use dig for reliable DNS resolution checking
    # If domain resolves, dig will output IP addresses; if not, no output
    local result=$(dig +short "$domain" 2>/dev/null)
    
    # Check if we got any output (domain resolves)
    if [[ -n "$result" ]]; then
        return 0  # Domain resolves
    else
        return 1  # Domain doesn't resolve
    fi
}

# Function to scan domain with httpx and get web info
scan_with_httpx() {
    local domain="$1"
    
    if [[ ${silent} == false ]]; then
        echo -e "${BLUE}[HTTP-SCAN]${NC} Running Httpx scan on $domain"
    fi
    
    # Run httpx with specified options and pipe output through notify
    httpx -u "$domain" -sc -server -td -fr -silent -title | notify -silent -id reconftw >/dev/null 2>&1 || true
}

# Function to scan ports with naabu
scan_with_naabu() {
    local domain="$1"
    
    if [[ ${silent} == false ]]; then
        echo -e "${BLUE}[PORT-SCAN]${NC} Running Naabu port scan on $domain"
    fi
    
    # Create a directory for naabu results
    mkdir -p "naabu_results"
    
    # Run naabu with common ports and save results
    naabu -host "$domain" -tp 1000 -silent -verify -c 50 -cdn -ec -nmap-cli "nmap -sV" -rate 2000 -o "naabu_results/${domain}.txt" | notify -silent -id reconftw -bulk 2>/dev/null &
}

# Function to scan for parameters with arjun
scan_with_arjun() {
    local domain="$1"
    
    if [[ ${silent} == false ]]; then
        echo -e "${BLUE}[PARAM-SCAN]${NC} Running Arjun parameter discovery on $domain"
    fi
    
    # Create a directory for arjun results
    mkdir -p "arjun_results"
    
    # Run arjun with specified options and save results
    arjun -u "https://$domain" -t 100 -oT "arjun_results/${domain}.txt" 2>/dev/null &
    
    
    # Check if any parameters were found
    if [[ -s "arjun_results/${domain}.txt" ]]; then
        if [[ ${silent} == false ]]; then
            local param_count=$(wc -l < "arjun_results/${domain}.txt")
            echo -e "${GREEN}[PARAMS]${NC} Found $param_count parameters on $domain" | notify -silent -id reconftw >/dev/null 2>&1 || true
        fi
    fi
}

# Function to scan for directories/files with dirsearch
scan_with_dirsearch() {
    local domain="$1"
    
    if [[ ${silent} == false ]]; then
        echo -e "${BLUE}[DIR-SCAN]${NC} Running Dirsearch directory scan on $domain"
    fi
    
    # Create a directory for dirsearch results
    mkdir -p "dirsearch_results"
    
    # Check if easy_wins.txt wordlist exists
    local wordlist="easy_wins.txt"
    if [[ ! -f "$wordlist" ]]; then
        echo -e "${RED}[ERROR]${NC} Wordlist file '$wordlist' not found!"
        echo -e "${YELLOW}[INFO]${NC} Please create the '$wordlist' file with your desired wordlist entries."
        echo -e "${YELLOW}[INFO]${NC} Skipping dirsearch scan for $domain"
        return 1
    fi
    
    # Run dirsearch with specified options and save results
    python3 -W ignore /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u "https://$domain/" -w "$wordlist" -q -F -i 200 --max-rate 40 -o "dirsearch_results/${domain}.txt" | notify -silent -id reconftw -bulk 2>/dev/null &
}

# Function to scan a domain with nuclei
scan_with_nuclei() {
    local domain="$1"
    local nuclei_output="nuclei_results.txt"
    
    if [[ ${silent} == false ]]; then
        echo -e "${BLUE}[SCAN]${NC} Running Nuclei scan on $domain"
    fi
    
    # Create a directory for nuclei results
    mkdir -p "nuclei_results"
    # Run nuclei with http templates and save results
    nuclei -target "https://$domain" -t /root/nuclei-templates/http/ -es info -rl 10 -et /root/nuclei-templates/http/exposures/ -silent -o "nuclei_results/${domain}.txt" | notify -id reconftw 2>/dev/null &
}

# Function to perform URL discovery and exposure scanning
scan_with_url_exposure() {
    local domain="$1"
    
    if [[ ${silent} == false ]]; then
        echo -e "${BLUE}[URL-EXPOSURE]${NC} Starting URL discovery and exposure scanning on $domain"
    fi
    
    # Create directories for results
    mkdir -p "gau_results"
    mkdir -p "katana_results"
    
    # Create a background process that handles the entire workflow
    (
        # Run gau for URL discovery
        gau "$domain" --blacklist png,jpg,gif,ico,svg --o "gau_results/${domain}-urls.txt" --fc 404 2>/dev/null &
        gau_pid=$!
        
        # Run katana URL crawling
        katana -u "$domain" -jc -silent -o "katana_results/${domain}-urls.txt" 2>/dev/null &
        katana_pid=$!
        
        # Wait for both gau and katana to complete
        wait $gau_pid
        wait $katana_pid
        
        # Combine results and create unique list
        if [[ -f "katana_results/${domain}-urls.txt" || -f "gau_results/${domain}-urls.txt" ]]; then
            cat "katana_results/${domain}-urls.txt" "gau_results/${domain}-urls.txt" 2>/dev/null | anew -q "all-expo-${domain}.txt"
            
            # Run nuclei exposure scan if URLs were found
            if [[ -s "all-expo-${domain}.txt" ]]; then
                nuclei -l "all-expo-${domain}.txt" -t /root/nuclei-templates/http/exposures/ -es info -rl 10 -silent -o "nuclei_results/expo-${domain}.txt" | notify -id reconftw 2>/dev/null &
            fi
        fi
    ) &
}

# Function to parse results from CertStream
parse_results() {
    all_domains_found=("$@")
    seen_domains=()

    for subdomain in "${all_domains_found[@]}"; do
        for target in "${targets[@]}"; do
            matched=false
            
            # Determine if target is a domain (contains a dot) or a string keyword
            if [[ $target == *.* ]]; then
                # Domain matching (strict) - target contains dots, treat as domain
                # Check if subdomain ends with the target domain (proper domain matching)
                if [[ $subdomain == *".$target" ]] || [[ $subdomain == "$target" ]]; then
                    matched=true
                fi
            else
                # String matching (flexible) - target has no dots, treat as keyword
                # Check if string appears anywhere in the subdomain
                if [[ $subdomain == *$target* ]]; then
                    matched=true
                fi
            fi
            
            if [[ $matched == true ]]; then
                # removing wildcards
                if [[ $subdomain == "*"* ]]; then
                    seen_domains+=("${subdomain:2}")
                else
                    seen_domains+=("$subdomain")
                fi
                break
            fi
        done
    done

    # we have a list of found domains now (which might be containing some duplicate entries)
    # Lets get rid of duplicate entries
    unique_subdomains=($(echo "${seen_domains[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

    # checking if domain already exists in already seen file
    for host in "${unique_subdomains[@]}"; do
        # Check if domain already exists in either file using grep
        # Create files if they don't exist
        [[ ! -f "$output_file" ]] && touch "$output_file"
        [[ ! -f "$resolved_file" ]] && touch "$resolved_file"
        
        # Check if domain exists in resolved file
        if grep -Fxq "$host" "$resolved_file" 2>/dev/null; then
            # Domain already exists in resolved file, skip processing
            continue
        fi
        
        # Check if domain exists in unresolved file  
        if grep -Fxq "$host" "$output_file" 2>/dev/null; then
            # Domain exists in unresolved file, check if it now resolves
            if check_dns_resolution "$host"; then
                # Domain now resolves - move from unresolved to resolved
                # Remove from unresolved file and add to resolved file
                grep -Fv "$host" "$output_file" > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
                echo "$host" >> "$resolved_file"
                
                if [[ ${silent} == true ]]; then
                    echo -e "[RESOLVED] $host (moved from unresolved)"
                else
                    echo -e "${GREEN}[RESOLVED]${NC} $host (moved from unresolved)" | tlsx -silent -cn 2>/dev/null || echo -e "${GREEN}[RESOLVED]${NC} $host (moved from unresolved)"
                fi
                
                # Send notification for newly resolved domain
                if [[ ${notify} == true ]]; then
                    echo -e "$host" | notify -silent -id certpolice >/dev/null 2>&1 || true
                fi
                
                # Run httpx scan first
                scan_with_httpx "$host"
                
                # Run naabu port scan if enabled
                if [[ ${naabu_scan} == true ]]; then
                    scan_with_naabu "$host"
                fi
                
                # Run arjun parameter scan if enabled
                if [[ ${arjun_scan} == true ]]; then
                    scan_with_arjun "$host"
                fi
                
                # Run dirsearch directory scan if enabled
                if [[ ${dirsearch_scan} == true ]]; then
                    scan_with_dirsearch "$host"
                fi
                
                # Run nuclei scan if enabled
                if [[ ${nuclei_scan} == true ]]; then
                    scan_with_nuclei "$host"
                fi
                
                # Run URL discovery and exposure scan if enabled
                if [[ ${url_exposure_scan} == true ]]; then
                    scan_with_url_exposure "$host"
                fi
            fi
            # If it still doesn't resolve, skip (already in unresolved file)
            continue
        fi
        
        # Domain is completely new - not in either file
        if check_dns_resolution "$host"; then
            # New domain that resolves - add to resolved file
            echo "$host" >> "$resolved_file"
            
            if [[ ${silent} == true ]]; then
                echo -e "[RESOLVED] $host"
            else
                echo -e "${GREEN}[RESOLVED]${NC} $host" | tlsx -silent -cn 2>/dev/null || echo -e "${GREEN}[RESOLVED]${NC} $host"
            fi
            
            # Send notification only for resolved domains
            if [[ ${notify} == true ]]; then
                echo -e "$host" | notify -silent -id certpolice >/dev/null 2>&1 || true
            fi
            
            # Run httpx scan first
            scan_with_httpx "$host"
            
            # Run naabu port scan if enabled
            if [[ ${naabu_scan} == true ]]; then
                scan_with_naabu "$host"
            fi
            
            # Run arjun parameter scan if enabled
            if [[ ${arjun_scan} == true ]]; then
                scan_with_arjun "$host"
            fi
            
            # Run dirsearch directory scan if enabled
            if [[ ${dirsearch_scan} == true ]]; then
                scan_with_dirsearch "$host"
            fi
            
            # Run nuclei scan if enabled
            if [[ ${nuclei_scan} == true ]]; then
                scan_with_nuclei "$host"
            fi
            
            # Run URL discovery and exposure scan if enabled
            if [[ ${url_exposure_scan} == true ]]; then
                scan_with_url_exposure "$host"
            fi
        else
            # New domain that doesn't resolve - add to unresolved file
            echo "$host" >> "$output_file"
            
            if [[ ${silent} == false ]]; then
                echo -e "${YELLOW}[UNRESOLVED]${NC} $host"
            fi
        fi
    done

}

# Start CertStream monitor and process JSON output with callback
print_callback() {
    local line_count=0
    
    while IFS= read -r line; do
        # Skip empty lines
        if [[ -z "$line" ]]; then
            continue
        fi
        
        line_count=$((line_count + 1))
        
        # Show periodic status updates (every 1000 lines processed)
        if [[ ${silent} == false && $((line_count % 1000)) -eq 0 ]]; then
            echo -e "${GREEN}[STATUS]${NC} Processed $line_count certificate entries..."
        fi
        
        # Check if the line contains certificate data with sans field
        if echo "$line" | jq -e '.sans.dns_names' >/dev/null 2>&1; then
            all_domains=($(echo "$line" | jq -r '.sans.dns_names[]? // empty' 2>/dev/null))
            if [[ ${#all_domains[@]} -gt 0 ]]; then
                parse_results "${all_domains[@]}"
            fi
        fi
    done
    
    # If we exit the loop, it means the stream ended
    if [[ ${silent} == false ]]; then
        echo -e "${YELLOW}[WARNING]${NC} CertStream ended after processing $line_count entries"
    fi
}

# Function to start CertStream with auto-reconnection
start_certstream() {
    local retry_count=0
    local max_retries=999999  # Essentially unlimited retries
    
    while [[ $retry_count -lt $max_retries ]]; do
        if [[ ${silent} == false ]]; then
            echo -e "${BLUE}[INFO]${NC} Starting Certificate Transparency monitoring... (Attempt: $((retry_count + 1)))"
        fi
        
        # Start certstream and handle connection
        if timeout 300 certstream --url "wss://ctlstream.interrupt.sh/stream" --full --json 2>/dev/null | print_callback; then
            if [[ ${silent} == false ]]; then
                echo -e "${GREEN}[INFO]${NC} CertStream exited normally"
            fi
        else
            local exit_code=$?
            if [[ ${silent} == false ]]; then
                if [[ $exit_code -eq 124 ]]; then
                    echo -e "${YELLOW}[WARNING]${NC} CertStream connection timeout (no data received for 5 minutes)"
                else
                    echo -e "${YELLOW}[WARNING]${NC} CertStream connection lost or failed (exit code: $exit_code)"
                fi
            fi
        fi
        
        # If we reach here, the connection was lost
        retry_count=$((retry_count + 1))
        
        if [[ $retry_count -lt $max_retries ]]; then
            if [[ ${silent} == false ]]; then
                echo -e "${YELLOW}[INFO]${NC} Connection lost. Reconnecting in 10 seconds..."
            fi
            sleep 10
        fi
    done
    
    echo -e "${RED}[ERROR]${NC} Maximum retry attempts reached. Exiting."
    exit 1
}

# Start CertStream monitor and process JSON output with callback

function initiate(){
	# Output files for saving subdomains
	output_file="found_subdomains.txt"        # For unresolved domains
	resolved_file="resolved_subdomains.txt"   # For resolved domains
	
	[[ ${silent} == false ]] && banner
	# Read target domains from the file
	if [[ -f "$target" && -s "$target" ]]; then
		targets=($(cat "$target"))
	else
		echo -e "${MAGENTA}Target file issue: File does not exist or is empty.${NC}"
		exit 1
	fi
	[[ ${silent} == false ]] && echo -e "${BLUE}[INFO]${NC} No. of domains/Keywords to monitor ${#targets[@]}"
	[[ ${silent} == false && "$notify" == true ]] && echo -e "${BLUE}[INFO]${NC} Notify is enabled (only for resolved domains)"
	[[ ${silent} == false ]] && echo -e "${BLUE}[INFO]${NC} Httpx web scanning is enabled for all resolved domains"
	[[ ${silent} == false && "$naabu_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Naabu port scanning is enabled for resolved domains"
	[[ ${silent} == false && "$arjun_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Arjun parameter discovery is enabled for resolved domains"
	[[ ${silent} == false && "$dirsearch_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Dirsearch directory scanning is enabled for resolved domains"
	[[ ${silent} == false && "$nuclei_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Nuclei scanning is enabled for resolved domains"
	[[ ${silent} == false && "$url_exposure_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} URL discovery and exposure scanning is enabled for resolved domains"
	[[ ${silent} == false ]] && echo -e "${BLUE}[INFO]${NC} Unresolved domains: $output_file"
	[[ ${silent} == false ]] && echo -e "${BLUE}[INFO]${NC} Resolved domains: $resolved_file"
	[[ ${silent} == false && "$naabu_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Naabu results: naabu_results/ directory"
	[[ ${silent} == false && "$arjun_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Arjun results: arjun_results/ directory"
	[[ ${silent} == false && "$dirsearch_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Dirsearch results: dirsearch_results/ directory"
	[[ ${silent} == false && "$nuclei_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Nuclei results: nuclei_results/ directory"
	[[ ${silent} == false && "$url_exposure_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} URL exposure results: gau_results/, katana_results/, all-expo-{domain}.txt files"
	
	# Start CertStream with auto-reconnection
	start_certstream
}

print_usage() {
	[[ ${silent} == false ]] && banner
	
	echo -e "${GREEN}USAGE:${NC}"
	echo -e "  $0 [OPTIONS] -t targets.txt"
	echo
	
	echo -e "${GREEN}REQUIRED:${NC}"
	echo -e "  -t, --target FILE     Target domains/keywords file"
	echo
	
	echo -e "${GREEN}BASIC OPTIONS:${NC}"
	echo -e "  -s, --silent          Run in silent mode (minimal output)"
	echo -e "  -n, --notify          Enable notifications for new domains"
	echo -e "  -h, --help            Show this help message"
	echo
	
	echo -e "${GREEN}SECURITY SCANNING:${NC}"
	echo -e "  -p, --naabu           Enable port scanning with naabu"
	echo -e "  -r, --arjun           Enable parameter discovery with arjun"
	echo -e "  -f, --dirsearch       Enable directory/file scanning with dirsearch"
	echo -e "  -u, --nuclei          Enable vulnerability scanning with nuclei"
	echo -e "  -e, --url-exposure    Enable URL discovery and exposure scanning"
	echo
	
	echo -e "${GREEN}COMMON EXAMPLES:${NC}"
	echo -e "  ${BLUE}# Basic monitoring${NC}"
	echo -e "  $0 -t targets.txt"
	echo
	echo -e "  ${BLUE}# With notifications${NC}"
	echo -e "  $0 -n -t targets.txt"
	echo
	echo -e "  ${BLUE}# Silent mode with notifications${NC}"
	echo -e "  $0 -s -n -t targets.txt"
	echo
	echo -e "  ${BLUE}# Full security scanning${NC}"
	echo -e "  $0 -p -r -f -u -e -t targets.txt"
	echo
	echo -e "  ${BLUE}# Everything enabled${NC}"
	echo -e "  $0 -s -n -p -r -f -u -e -t targets.txt"
	echo
	
	echo -e "${GREEN}SCANNING WORKFLOW:${NC}"
	echo -e "  1. ${YELLOW}Httpx${NC} - Web scanning (always enabled)"
	echo -e "  2. ${YELLOW}Naabu${NC} - Port scanning (-p flag)"
	echo -e "  3. ${YELLOW}Arjun${NC} - Parameter discovery (-r flag)"
	echo -e "  4. ${YELLOW}Dirsearch${NC} - Directory/file scanning (-f flag)"
	echo -e "  5. ${YELLOW}Nuclei${NC} - Vulnerability scanning (-u flag)"
	echo -e "  6. ${YELLOW}URL Exposure${NC} - URL discovery + exposure scanning (-e flag)"
	echo
	
	echo -e "${GREEN}OUTPUT FILES:${NC}"
	echo -e "  found_subdomains.txt     - Unresolved domains"
	echo -e "  resolved_subdomains.txt  - Active/resolved domains"
	echo -e "  naabu_results/           - Port scan results"
	echo -e "  arjun_results/           - Parameter discovery results"
	echo -e "  dirsearch_results/       - Directory/file scan results"
	echo -e "  nuclei_results/          - Vulnerability scan results"
	echo -e "  gau_results/             - GAU URL discovery results"
	echo -e "  katana_results/          - Katana URL crawling results"
	echo -e "  all-expo-{domain}.txt    - Combined URLs for exposure scanning"
	echo
}


target_file=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      print_usage
      exit 0
      ;;
    -s|--silent)
      silent=true
      shift
      ;;
    -n|--notify)
      notify=true
      shift
      ;;
    -p|--naabu)
      naabu_scan=true
      shift
      ;;
    -r|--arjun)
      arjun_scan=true
      shift
      ;;
    -f|--dirsearch)
      dirsearch_scan=true
      shift
      ;;
    -u|--nuclei)
      nuclei_scan=true
      shift
      ;;
    -e|--url-exposure)
      url_exposure_scan=true
      shift
      ;;
    -t|--target)
      target_file="$2"
      shift 2
      ;;
    -*|--*)
      echo "Unknown option $1"
      print_usage
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

# Check if target file was provided and initiate monitoring
if [[ -n "$target_file" ]]; then
    target="$target_file"
    initiate
else
    print_usage
    exit 1
fi
