# Meta options
complete -c dog -s 'v' -l 'version' -d "Show version of dog"
complete -c dog -s '?' -l 'help'    -d "Show list of command-line options"

# Query options
complete -c dog -x -a "(__fish_print_hostnames) A AAAA CAA CNAME HINFO MX NS PTR SOA SRV TXT IN CH HS"
complete -c dog -s 'q' -l 'query'      -d "Host name or domain name to query" -x -a "(__fish_print_hostnames)"
complete -c dog -s 't' -l 'type'       -d "Type of the DNS record being queried" -x -a "A AAAA CAA CNAME HINFO MX NS PTR SOA SRV TXT"
complete -c dog -s 'n' -l 'nameserver' -d "Address of the nameserver to send packets to" -x -a "(__fish_print_hostnames)"
complete -c dog        -l 'class'      -d "Network class of the DNS record being queried" -x -a "IN CH HS"

# Sending options
complete -c dog        -l 'edns'       -d "Whether to OPT in to EDNS" -x -a "
    disable\t'Do not send an OPT query'
    hide\t'Send an OPT query, but hide the result'
    show\t'Send an OPT query, and show the result'
"
complete -c dog        -l 'txid'       -d "Set the transaction ID to a specific value" -x
complete -c dog -s 'Z'                 -d "Configure uncommon protocol-level tweaks" -x -a "
    aa\t'Set the AA (Authoritative Answers) query bit'
    ad\t'Set the AD (Authentic Data) query bit'
    bufsize=\t'Set the UDP payload size'
    cd\t'Set the CD (Checking Disabled) query bit'
"

# Protocol options
complete -c dog -s 'U' -l 'udp'        -d "Use the DNS protocol over UDP"
complete -c dog -s 'T' -l 'tcp'        -d "Use the DNS protocol over TCP"
complete -c dog -s 'S' -l 'tls'        -d "Use the DNS-over-TLS protocol"
complete -c dog -s 'H' -l 'https'      -d "Use the DNS-over-HTTPS protocol"

# Output options
complete -c dog -s '1' -l 'short'      -d "Display nothing but the first result"
complete -c dog -s 'J' -l 'json'       -d "Display the output as JSON"
complete -c dog        -l 'color'      -d "When to colorise the output" -x -a "
    always\t'Always use colors'
    automatic\t'Use colors when printing to a terminal'
    never\t'Never use colors'
"
complete -c dog        -l 'colour'     -d "When to colourise the output" -x -a "
    always\t'Always use colours'
    automatic\t'Use colours when printing to a terminal'
    never\t'Never use colours'
"
complete -c dog        -l 'seconds'    -d "Do not format durations, display them as seconds"
complete -c dog        -l 'time'       -d "Print how long the response took to arrive"
