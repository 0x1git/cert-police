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

}

required_tools=("pv" "anew" "python3" "pip" "jq" "nslookup" "certstream" "notify" "tlsx" "nuclei")

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
    nuclei -target "https://$domain" -t /root/nuclei-templates/http/ -es info -silent -o "nuclei_results/${domain}.txt" | notify -id reconftw 2>/dev/null
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
                
                # Run nuclei scan if enabled
                if [[ ${nuclei_scan} == true ]]; then
                    scan_with_nuclei "$host"
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
            
            # Run nuclei scan if enabled
            if [[ ${nuclei_scan} == true ]]; then
                scan_with_nuclei "$host"
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
	[[ ${silent} == false && "$nuclei_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Nuclei scanning is enabled for resolved domains"
	[[ ${silent} == false ]] && echo -e "${BLUE}[INFO]${NC} Unresolved domains: $output_file"
	[[ ${silent} == false ]] && echo -e "${BLUE}[INFO]${NC} Resolved domains: $resolved_file"
	[[ ${silent} == false && "$nuclei_scan" == true ]] && echo -e "${BLUE}[INFO]${NC} Nuclei results: nuclei_results/ directory"
	
	# Start CertStream with auto-reconnection
	start_certstream
}

print_usage() {
	[[ ${silent} == false ]] && banner
	echo "$0 --silent --notify --target targets.txt"
	echo "$0 -s -n -t targets.txt"
	echo "$0 --add \"STRING\" --target targets.txt"
	echo "$0 -a \"STRING\" -t targets.txt"
	echo "$0 --nuclei -t targets.txt (enable nuclei scanning)"
	echo "$0 -u -t targets.txt (enable nuclei scanning)"
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
    -u|--nuclei)
      nuclei_scan=true
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
