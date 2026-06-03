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
	echo -e "\n${CYAN}${BOLD}=================================================================${RESET}";  \
	echo -e "${CYAN}${BOLD}     $*${RESET}"; 	
	echo -e "${CYAN}${BOLD}=================================================================${RESET}";
}

subhead() {
	echo -e "\n${CYAN}${BOLD}------------------$*--------------------${RESET}";	
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

header "1. Listening Ports & Processes"
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

#===================================================================================
#2.  LAST 10 FAILED LOGIN ATTEMPTS
#===================================================================================

header "2. Last 10 Failed Login Attempts"

AUTH_LOG=" "
for f in /var/log/auth.log  /var/log/secure ; do
	[[ -f  "$f" ]] && AUTH_LOG="$f" && break
done
if [[ -n "AUTH_LOG" ]] ; then
	FAILS=$( grep -i "failed\ | failure\ | invalid"  "$AUTH_LOG" 2>/dev/null | tail -10 )
	COUNT=$( echo "$FAILS" | grep -c . )
	if [[ $COUNT -eq 0 ]] ; then
		ok "No failed login attempts found in $AUTH_LOG. "
	elif [[ $COUNT -ge 5 ]]; then
		critical "Found $COUNT recent failed logins - possible brute-force activity !"
		echo "$FAILS | while read -r line; do critical  "$line"; done"
	else 
		warn "Found $COUNT recent failed logins."
		echo "$FAILS | while read -r line; do warn "$line"; done "
	fi
else 
	warn "Auth log not found at /var/log/auth.log or /var/log/secure. "
	warn "Install rsyslog or check your distros log path."
fi

#===================================================================================
#3. WORD-WRITABLE FILES IN /etc AND /tmp
#===================================================================================

header "3. Word-Writable Files in /etc and /tmp"

subhead "/etc - word writable files"

ETC_WW=$( find /etc -xdev -type f -perm -o+w 2>/dev/null )
if [[ -z "$ETC_WW" ]]; then
	ok "No Word-Writable files found in /etc"
else
	critical "Word-Writable files found in /etc - this is a serious risk!"
       echo "$ETC_WW" | while  read -r f; do critical "$f" ; done
fi

subhead "/tmp - Word-Writable files ( excluding sticky-bit dirs )"

TMP_WW=$( find /tmp -xdev -type f -prem  -o+w 2>/dev/null )
TMP_COUNT=$( echo "$TMP_WW" | grep -c . )
if [[ $TMP_COUNT -eq 0 ]] ; then 
	ok "No unexpected word-writable files in /tmp."
elif [[ $TMP_COUNT -le 5 ]] ; then
	warn "$TMP_COUNT word-writable file(s) in /tmp:"
	echo "$TMP_WW" | while read -r f; do warn "$f" ; done
else
	critical "$TMP_COUNT word-writable files in /tmp - review immediately:"
	echo "$TMP_WW" | while read -r f; do critical "$f" ; done 
fi

#===================================================================================
#4. USERS WITH SUDO PRIVILEGES
#===================================================================================
 
header "4. Users with Sudo Privileges"

subhead "Members of sudo/wheel group"
SUDO_USERS= ""
for grp in sudo wheel admin; do
	MEMBERS=$( getent group "$grp" 2>/dev/null | cut -d : -f4 )
	if [[ -n "$MEMBERS" ]] ; then
		warn "Group '$grp' : $MEMBERS"
		SUDO_USERS="$SUDO_USERS $MEMBERS"
	fi
done
[[ -z "$SUDO_USERS" ]] && ok "No users found in sudo/wheel groups."

subhead "Sudoer file entries"
grep -v '^\s*#' /etc/sudoers 2>/dev/null | grep -v '^\s*$' | while read -r line ; do
	if  echo "$line" | grep -q "ALL=(ALL)"; then
		critical "Unrestricted sudo: $line"
	else
		warn "Sudoers entry: $line"
	fi
done

subhead "Sudoers.d directory"
if [[ -d /etc/sudoers.d ]]; then
	FILES=$( ls /etc/sudoers.d/ 2>/dev/null )
	if [[ -z "$FILES" ]]; then
		ok "No files in /etc/sudoers.d."
	else 
		warn "Additional sudoers files found:"
		for f in $FILES; do
			warn "    /etc/sudoers.d/$f"
		done
	fi
fi

#===================================================================================
#5. UFW FIREWALL STATUS
#===================================================================================
 
header "5. UFW Firewall Status"

if command -v ufw &>/dev/null; then
	UFW_STATUS=$( ufw status 2>/dev/null )
	if echo "$UFW_STATUS" | grep -qi "Status: active"; then
		ok "UFW is ACTIVE."
		echo "$UFW_STATUS" | tail -n +4 |while read -r line; do
			[[ -n "$line" ]] && ok "    $line"
		done
	else 
		critical "UFW is INACTIVE - your machine has no firewall protection! "
		warn "Run: sudo ufw enable"
	fi
else
	warn "UFW not installed. Check for iptables/nftables instead."
	if command -v iptables &>/dev/null; then
		IPT=$( iptables -L -n --line-numbers 2>/dev/null | grep -cc "^[0-9]" )
		[[ $IPT -gt 0 ]] && ok "iptables has $IPT rules active." \
						  || warn "iptables has no rules - firewall may be open."
	else 
		critical  "No firewall tool (ufw/iptables) detected."
	fi
fi
#===================================================================================
#6. RUNNING SERVICES
#===================================================================================

header "6. Running Services (systemctl)"

