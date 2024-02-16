# Meta options
complete -c doge -s 'v' -l 'version' -d "Show version of doge"
complete -c doge -s '?' -l 'help'    -d "Show list of command-line options"

# Query options
complete -c doge -x -a "(__fish_print_hostnames) A AAAA CAA CNAME HINFO MX NS PTR SOA SRV TXT IN CH HS"
complete -c doge -s 'q' -l 'query'      -d "Host name or domain name to query" -x -a "(__fish_print_hostnames)"
complete -c doge -s 't' -l 'type'       -d "Type of the DNS record being queried" -x -a "A AAAA CAA CNAME HINFO MX NS PTR SOA SRV TXT"
complete -c doge -s 'n' -l 'nameserver' -d "Address of the nameserver to send packets to" -x -a "(__fish_print_hostnames)"
complete -c doge        -l 'class'      -d "Network class of the DNS record being queried" -x -a "IN CH HS"

# Sending options
complete -c doge        -l 'edns'       -d "Whether to OPT in to EDNS" -x -a "
    disable\t'Do not send an OPT query'
    hide\t'Send an OPT query, but hide the result'
    show\t'Send an OPT query, and show the result'
"
complete -c doge        -l 'txid'       -d "Set the transaction ID to a specific value" -x
complete -c doge -s 'Z'                 -d "Configure uncommon protocol-level tweaks" -x -a "
    aa\t'Set the AA (Authoritative Answers) query bit'
    ad\t'Set the AD (Authentic Data) query bit'
    bufsize=\t'Set the UDP payload size'
    cd\t'Set the CD (Checking Disabled) query bit'
"

# Protocol options
complete -c doge -s 'U' -l 'udp'        -d "Use the DNS protocol over UDP"
complete -c doge -s 'T' -l 'tcp'        -d "Use the DNS protocol over TCP"
complete -c doge -s 'S' -l 'tls'        -d "Use the DNS-over-TLS protocol"
complete -c doge -s 'H' -l 'https'      -d "Use the DNS-over-HTTPS protocol"

# Output options
complete -c doge -s '1' -l 'short'      -d "Display nothing but the first result"
complete -c doge -s 'J' -l 'json'       -d "Display the output as JSON"
complete -c doge        -l 'color'      -d "When to colorise the output" -x -a "
    always\t'Always use colors'
    automatic\t'Use colors when printing to a terminal'
    never\t'Never use colors'
"
complete -c doge        -l 'colour'     -d "When to colourise the output" -x -a "
    always\t'Always use colours'
    automatic\t'Use colours when printing to a terminal'
    never\t'Never use colours'
"
complete -c doge        -l 'seconds'    -d "Do not format durations, display them as seconds"
complete -c doge        -l 'time'       -d "Print how long the response took to arrive"
