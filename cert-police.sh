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
  echo "Cleaning up before exit"
  exit 0
}

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
    if ! check_exist certstream; then
        echo "${YELLOW}[*] Installing certstream ${NC}"
	pip install certstream --break-system-packages 2>/dev/null | pv -p -t -e -N "Installing Tool: certstream" >/dev/null
    fi
    if ! check_exist notify; then
        echo "${YELLOW}[*] Installing jq ${NC}"
        go install -v github.com/projectdiscovery/notify/cmd/notify@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Notify" >/dev/null
    fi
    if ! check_exist tlsx; then
        echo "${YELLOW}[*] Installing jq ${NC}"
        go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: TLSx" >/dev/null
    fi

}

required_tools=("pv" "anew" "python3" "pip" "jq" "certstream" "notify" "tlsx")

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

trap cleanup SIGINT

# Initialize variables
silent=false
notify=false
targets=()  # Global array for target domains and keywords
POSITIONAL_ARGS=()  # Array to store positional arguments

# Function to extract and parse subdomains with both domain and string matching
# Supports two matching modes:
# 1. Domain matching (strict) - for targets with dots (e.g., "principal.com")
#    Only matches actual subdomains: "api.principal.com" ✅, "notprincipal.com" ❌
# 2. String matching (flexible) - for targets without dots (e.g., "shopee", "garena")  
#    Matches if string appears anywhere: "files.garena.vn" ✅, "supply.shopee.com.my" ✅
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
        if [[ ${silent} == true ]]; then
            echo -e "$host"
        else
            echo -e "$host" | tlsx -silent -cn 2>/dev/null || echo -e "$host"
        fi
        echo -e "$host" | anew -q "$output_file" 2>/dev/null
        if [[ ${notify} == true ]]; then
            echo -e "$host" | notify -silent -id certpolice >/dev/null 2>&1 || true
        fi
    done

}

# Start CertStream monitor and process JSON output with callback
print_callback() {
    while IFS= read -r line; do
        # Skip empty lines
        if [[ -z "$line" ]]; then
            continue
        fi
        
        # Check if the line contains certificate data with sans field
        if echo "$line" | jq -e '.sans.dns_names' >/dev/null 2>&1; then
            all_domains=($(echo "$line" | jq -r '.sans.dns_names[]? // empty' 2>/dev/null))
            if [[ ${#all_domains[@]} -gt 0 ]]; then
                parse_results "${all_domains[@]}"
            fi
        fi
    done
}

# Start CertStream monitor and process JSON output with callback

function initiate(){
	# Output file for saving subdomains
	output_file="found_subdomains.txt"
	[[ ${silent} == false ]] && banner
	# Read target domains from the file
	if [[ -f "$target" && -s "$target" ]]; then
		targets=($(cat "$target"))
	else
		echo -e "${MAGENTA}Target file issue: File does not exist or is empty.${NC}"
		exit 1
	fi
	[[ ${silent} == false ]] && echo -e "${BLUE}[INFO]${NC} No. of domains/Keywords to monitor ${#targets[@]}"
	[[ ${silent} == false && "$notify" == true ]] && echo -e "${BLUE}[INFO]${NC} Notify is enabled"
	# Start CertStream monitor and process JSON output with callback
	echo -e "${BLUE}[INFO]${NC} Starting Certificate Transparency monitoring..."
	certstream --url "wss://ctlstream.interrupt.sh/stream" --full --json 2>/dev/null | print_callback
}

print_usage() {
	[[ ${silent} == false ]] && banner
	echo "$0 --silent --notify --target targets.txt"
	echo "$0 -s -n -t targets.txt"
	echo "$0 --add \"STRING\" --target targets.txt"
	echo "$0 -a \"STRING\" -t targets.txt"
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
