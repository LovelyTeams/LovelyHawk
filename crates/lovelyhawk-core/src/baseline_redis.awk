# Candidate-file findings only: files are not assumed to belong to one running
# instance. Last scalar directive wins within a file; another candidate cannot
# erase its risk. Includes, ACLs and CONFIG SET require instance verification.
# Output is a closed set of risk tokens, never passwords, hashes or ACL rules.
function reset_words(    part) {
    for (part in words) delete words[part]
    count = 0; token = ""; started = 0; quote = ""; closed_quote = 0; invalid = 0
}
function finish_word() {
    if (started) {
        count++
        if (count <= 64) words[count] = token
        else invalid = 1
    }
    token = ""; started = 0; closed_quote = 0
}
function finding(value) {
    if (risk == "") { risk = value; source = current_file }
}
function unspecified_ipv6(address,    copy, compressions, parts, group, groups, nonempty) {
    copy = address
    compressions = gsub(/::/, "x", copy)
    if (compressions > 1 || (substr(address, 1, 1) == ":" && substr(address, 1, 2) != "::") ||
        (substr(address, length(address)) == ":" && substr(address, length(address)-1) != "::")) return 0
    parts = split(address, groups, ":"); nonempty = 0
    for (group = 1; group <= parts; group++) {
        if (groups[group] == "") continue
        if (length(groups[group]) > 4 || groups[group] !~ /^0+$/) return 0
        nonempty++
    }
    return compressions == 1 ? nonempty <= 7 : nonempty == 8
}
function finish_file() {
    if (current_file == "" || file_invalid) return
    if (k == "protected-mode" && scalar == "no") finding("no")
    else if ((k == "enable-debug-command" || k == "enable-module-command") &&
             (scalar == "yes" || scalar == "local")) finding(scalar)
    else if (k == "bind" && wildcard != "") finding(wildcard)
    else if (k == "requirepass" && !acl && !includes && !password) finding("no-auth-directive")
    else if (k == "logfile" && scalar == "/dev/null") finding("/dev/null")
}
FNR == 1 {
    finish_file()
    current_file = FILENAME; scalar = ""; wildcard = ""; password = 0
    acl = 0; includes = 0; file_invalid = 0; file_bytes = 0
}
{
    file_bytes += length($0) + 1
    if (file_bytes > 524288 || length($0) > 16384) { file_invalid = 1; next }
    if ($0 ~ /^[[:space:]]*(#|$)/) next
    reset_words()
    for (position = 1; position <= length($0); position++) {
        character = substr($0, position, 1)
        # Escaped tokens need Redis's exact binary string parser. They are not
        # simplified into a potentially different value by this risk reader.
        if (character == "\\") { invalid = 1; break }
        if (quote != "") {
            if (character == quote) { quote = ""; closed_quote = 1 }
            else token = token character
        } else if (character ~ /[[:space:]]/) {
            finish_word()
        } else if (closed_quote) {
            invalid = 1; break
        } else if (character == "\"" || character == "'") {
            if (started) { invalid = 1; break }
            quote = character; started = 1
        } else {
            token = token character; started = 1
        }
        if (length(token) > 256) { invalid = 1; break }
    }
    finish_word()
    if (invalid || quote != "") { file_invalid = 1; next }
    directive = tolower(words[1])
    if (directive == "include") includes = 1
    if (directive == "aclfile" || directive == "user") acl = 1
    if (directive != k) next
    if (candidate_source == "") candidate_source = FILENAME
    if (k == "bind") {
        wildcard = ""
        for (part = 2; part <= count; part++) {
            address = words[part]; sub(/^-/, "", address)
            if (address == "0.0.0.0" || address == "*" || address == "::*" ||
                (index(address, ":") && unspecified_ipv6(address))) wildcard = address
        }
    } else if (k == "requirepass") {
        if (count != 2) file_invalid = 1
        else password = (words[2] != "")
    } else if (k != "rename-command") {
        if (count != 2) file_invalid = 1
        else scalar = (k == "logfile" ? words[2] : tolower(words[2]))
    }
}
END { finish_file(); print (risk == "" ? "__unverified__" : risk) }
