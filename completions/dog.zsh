#compdef dog

__dog() {
    _arguments \
        "(- 1 *)"{-v,--version}"[Show version of dog]" \
        "(- 1 *)"{-\?,--help}"[Show list of command-line options]" \
        {-q,--query}"[Host name or IP address to query]::_hosts" \
        {-t,--type}"[Type of the DNS record being queried]:(record type):(A AAAA CAA CNAME HINFO MX NS PTR SOA SRV TXT)" \
        {-n,--nameserver}"[Address of the nameserver to send packets to]::_hosts;" \
        --class"[Network class of the DNS record being queried]:(network class):(IN CH HS)" \
        --edns"[Whether to OPT in to EDNS]:(edns setting):(disable hide show)" \
        --txid"[Set the transaction ID to a specific value]" \
        -Z"[Configure uncommon protocol-level tweaks]:(protocol tweak):(aa ad bufsize= cd)" \
        {-U,--udp}"[Use the DNS protocol over UDP]" \
        {-T,--tcp}"[Use the DNS protocol over TCP]" \
        {-S,--tls}"[Use the DNS-over-TLS protocol]" \
        {-H,--https}"[Use the DNS-over-HTTPS protocol]" \
        {-1,--short}"[Display nothing but the finst result]" \
        {-J,--json}"[Display the output as JSON]" \
        {--color,--colour}"[When to use terminal colours]:(setting):(always automatic never)" \
        --seconds"[Do not format durations, display them as seconds]" \
        --time"[Print how long the response took to arrive"] \
        '*:filename:_hosts'
}

__dog
