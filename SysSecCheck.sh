#!/bin/bash
 
#   ===============================================================================================================================================
#  
#	SystemSecCheck  -  Linux System  Security Auditer
#	Author   :   Vyom Dharni 
#	Version   :   1.0.0
#
#   ===============================================================================================================================================


#------ Colour Codes --------------------------------------------------------------------------------------------------------------------------------------------

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'


#------Helper print functions------------------------------------------------------------------------------------------------------------------------------------

ok()  {
	echo -e "${GREEN}          [OK]${RESET}          $*";       
}

warn() {
	echo -e "${YELLOW}          [WARN]${RESET}          $*";
}

critical() {
	echo -e "${RED}          [CRITICAL]${RESET}          $*";
}

header() {	
	echo -e "\n${CYAN}${BOLD}================================================================${RESET}";  \
	echo -e "${CYAN}${BOLD}     $*${RESET}";    \
	echo -e "$CYAN}${BOLD} =================================================================${RESET}";
}

subhead() {
	echo -e "\n${BOLD}------------------$*--------------------${RESET}";	
}


#------Root check-----------------------------------------------------------------------------------------------------------------------------------------------
if [[  $EUID  -ne  0 ]]; then
	echo -e "${RED} [!]  This script must be run as root (use sudo).${RESET} "
	exit 1
fi

clear
echo -e "${CYAN}${BOLD}"
echo -e   "||==========================================================||"
echo -e  "||                                             SysSecCheck  -  Security Audit                                                               ||"
echo -e  "||                                             Date  :  $(date  "+%Y-%m-%d  %H:%M:%S" )                           ||"
echo -e  "||                                             Host  :  $(hostname)                                                                                   ||"
echo -e  "||==========================================================||"
echo -e  "${RESET}"


#===================================================================================
#1.   LISTENING PORTS AND ASSOCIATED PROCESSES
#==================================================================================

if -command -v ss &>/dev/null; then
	PORT_DATA=$(ss -tulnp 2>/dev/null)
elif command -v netstat &>/dev/null; then
	PORT_DATA=$(netstat -tulnp 2>/dev/null)
else  
	critical "Neither 'ss' nor 'netstat' found."
fi

if [[ -n "$PORT_DATA" ]]; then
	echo "$PORT_DATA" | head -1
	echo "$PORT_DATA" | tail -n +2 | while read -r line;  do
	port=$(echo "$line" | awk '{print$5}' | grep -oE '[0-9]+$') 
		if echo "$port" | grep -qE '^(21|23|3306|5432|27017)$'; then
			critical "$line"
		elif echo"$port" | grep -qE '^(22|80|443|8080|8943)$'; then
			warn "$line"
		else
			ok "$line"
		fi
	done
else
	warn "Could not retrieve port information."
fi

