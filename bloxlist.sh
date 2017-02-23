#!/bin/bash
# filename: bloxlist.sh
# george.g.larson@gmail.com
# http://j0rg3.com

#   A quick and dirty script to pull down a variety of blocklists
#   and put the constituent offenders  on the you-can't-come-list using ipset
#   will obviously need work for ipv6
#   perhaps expand into more robust application with config and SQLite3 goings-on

# Let's send our output to screen and log; just log if non-interactive
# cron, for example runs in a non-interactive shell 
# therefore usually no prompt is defined 
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
if [ -z "$PS1" ]; then
   exec 1>/var/log/bloxlist.log 2>&1
else
   exec 1|tee /var/log/bloxlist.log 2>&1
fi


set -uo pipefail

for arg in "$@"
do
    case "$arg" in
    -v)     set -x   
            ;;
    esac
done

date

# clean files down to IP addresses or ranges
function clean() {

# we'll look for the regex-complex format first which is a hypehnated-range (e.g., 127.0.0.1-127.255.255.255)
# then CIDR mask, then single IP address
# soon as grep gives us a positive return vale, that file is considered processed so we move on

# does file contain IP ranges?
if grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" $1 >> $1.tmp; then
   echo -e "[ INFO ] Found hyphenated IP ranges in $1\n"

# does file contain CIDRs?
elif grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/.(?[0-9][0-9]?)" $1 >> $1.tmp; then
   echo -e "[ INFO ] Found CIDR ranges in $1\n"

# find single IP addresses
elif grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" $1 >> $1.tmp; then
   echo -e "[ INFO ] Found single IP addresses in $1\n"

# nuffin' found
else
   echo -e "[ ERROR ] No IP addresses found in $1\n"
   #exit;  #bail?
fi

   # strip out tab characters
   sed -i 's/\t//g' $1.tmp

   # put our list in order
   sort -u $1.tmp | tee $1

   # clean up temp file
   rm $1.tmp

   # just a little informational output
   wc -l $1
}

# use ipset to say "Thanks, but... uhm...  I gave at the office"
function block() {
   echo -e "[ INFO ] Blocking IP addresses listed in $1...\n"
   ipset -exist create $1 hash:net
   ipset flush $1

   if hash ipset 2>/dev/null
   then
      while IFS= read -r ip
      do
         ipset add $1 $ip
      done < $1
   else
      echo -e '\nipset not found\n'
      exit
   fi

   iptables -I INPUT -m set --match-set $1 src -j DROP
}


# Wizcraft ilists to block broad swaths
WIZ_LISTS="chinese nigerian russian lacnic exploited-servers"

# define our list of blacklists
BLACKLISTS=(
"http://danger.rulez.sk/projects/bruteforceblocker/blist.php"  # BruteForceBlocker IP List
"http://www.openbl.org/lists/base.txt" # Open BlockList
"http://rules.emergingthreats.net/blockrules/compromised-ips.txt"  # Emerging Threats - Compromised IPs 
"http://cinsscore.com/list/ci-badguys.txt"  # C.I. Army Malicious IP List 
"http://www.openbl.org/lists/base.txt"  # OpenBL.org 90 day List 
"http://lists.blocklist.de/lists/all.txt"  # blocklist.de attackers 
"http://report.rutgers.edu/DROP/attackers" # Rutgers.edu 
"https://zeustracker.abuse.ch/blocklist.php?download=hostsdeny" # abuse.ch Zeus 
"http://www.spamhaus.org/drop/drop.txt"  # Spamhaus Don't Route Or Peer List (DROP) 
"http://www.spamhaus.org/drop/edrop.txt"  # Spamhaus Don't Route Or Peer List (DROP) Extended 
"https://sslbl.abuse.ch/blacklist/sslipblacklist.csv" # abuse.ch SSL
"http://panwdbl.appspot.com/lists/dshieldbl.txt" # SANS dshield 
"http://panwdbl.appspot.com/lists/mdl.txt" # Malware Domain List
############  You will need an API key (i.e., to make an account) with Autoshun to use the list below
#"http://www.autoshun.org/files/shunlist.csv"  # Autoshun Shun List 
)

# fetch and process our blacklist files
for address in "${BLACKLISTS[@]}"
do
   filename=`basename $address`.blx
   echo -e "\nFetching $address\n"
   curl "$address" > $filename
   clean $filename
   block $filename
done

# fetch and process our Wiz lists
for list in $WIZ_LISTS
do
   filename=wiz.$list.blx
   wget "http://www.wizcrafts.net/$list-iptables-blocklist.html" -O - >> $filename
   clean $filename
   block $filename
done

# one off that's gzipped
filename=uceprotect.blx
wget 'http://wget-mirrors.uceprotect.net/rbldnsd-all/dnsbl-3.uceprotect.net.gz' -O - | gunzip | tee -a $filename
clean $filename
block $filename

# clean up leftover mess
rm *.blx



