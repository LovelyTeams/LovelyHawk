# Candidate configuration findings, never effective settings. A later scalar
# overrides earlier scalars in that file, but a different candidate may belong
# to another cluster. Includes and runtime/session overrides require an instance.
# Return only closed finding tokens, not arbitrary configuration values.
function finish_file(    number, addresses, part, address) {
    if (current_file == "" || file_invalid || risk != "") return
    if (k == "listen_addresses") {
        number = split(scalar, addresses, ",")
        for (part = 1; part <= number; part++) {
            address = addresses[part]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", address)
            if (address == "*" || address == "0.0.0.0" || address == "::" || address == "0:0:0:0:0:0:0:0") {
                risk = "wildcard-listen"; break
            }
        }
    } else if (k == "password_encryption" && tolower(scalar) == "md5") risk = "md5"
    else if (k == "log_statement" && tolower(scalar) == "none") risk = "none"
    else if ((k == "ssl" || k == "log_connections" || k == "log_disconnections") &&
             tolower(scalar) ~ /^(0|n|no|f|fa|fal|fals|false|of|off)$/) risk = "off"
    # logging_collector alone cannot prove whether stderr/syslog/container
    # output is retained. It always needs the actual logging chain checked.
    if (risk != "") source = current_file
}
FNR == 1 {
    finish_file()
    current_file = FILENAME; scalar = ""; file_invalid = 0; file_bytes = 0
}
{
    file_bytes += length($0) + 1
    if (file_bytes > 524288 || length($0) > 16384) { file_invalid = 1; next }
    line = $0; sub(/^[[:space:]]+/, "", line)
    if (line ~ /^(#|$)/) next
    if (!match(line, /^[A-Za-z_][A-Za-z0-9_.]*/)) { file_invalid = 1; next }
    key = tolower(substr(line, 1, RLENGTH)); tail = substr(line, RLENGTH + 1)
    if (tail !~ /^[[:space:]=]/) { file_invalid = 1; next }
    sub(/^[[:space:]]+/, "", tail)
    if (substr(tail, 1, 1) == "=") { tail = substr(tail, 2); sub(/^[[:space:]]+/, "", tail) }
    value = ""; closed = 0; invalid = 0
    if (substr(tail, 1, 1) == "'") {
        for (position = 2; position <= length(tail); position++) {
            character = substr(tail, position, 1)
            # Escapes need PostgreSQL's native parser; never simplify them.
            if (character == "\\" || character ~ /[[:cntrl:]]/) { invalid = 1; break }
            if (character == "'") {
                if (substr(tail, position + 1, 1) == "'") { value = value "'"; position++ }
                else { closed = 1; position++; break }
            } else value = value character
        }
        remainder = substr(tail, position); sub(/^[[:space:]]+/, "", remainder)
        if (!closed || remainder !~ /^(#|$)/) invalid = 1
    } else {
        value = tail; sub(/#.*/, "", value); sub(/[[:space:]]+$/, "", value)
        if (value !~ /^[A-Za-z0-9_.+-]+$/) invalid = 1
    }
    if (invalid) { file_invalid = 1; next }
    if (key == k) {
        if (candidate_source == "") candidate_source = FILENAME
        scalar = value
    }
}
END { finish_file(); print (risk == "" ? "__unverified__" : risk) }
