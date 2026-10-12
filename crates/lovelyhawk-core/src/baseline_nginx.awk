# Candidate-file findings only. This does not resolve includes, inheritance,
# command-line overrides or the configuration loaded by a running master.
# A safe-looking occurrence must never erase an earlier risky scope, and
# absence of a risky token is not proof that the instance is configured safely.
function clear_directive() {
    count = 0; token = ""; started = 0; quote = ""; escaped = 0
    for (part in words) delete words[part]
}
function finish_token() {
    if (started) {
        count++
        if (count <= 64) words[count] = token
    }
    token = ""; started = 0
}
function finding(value) {
    if (risk == "") { risk = value; source = FILENAME }
}
function finish_directive(    i) {
    finish_token()
    if (words[1] == k && count <= 64) {
        if (source == "") source = FILENAME
        if ((k == "server_tokens" || k == "autoindex") && count == 2) {
            if (words[2] == "on" || (k == "server_tokens" && words[2] == "build"))
                finding(words[2])
        } else if (k == "ssl_protocols") {
            for (i = 2; i <= count; i++)
                if (words[i] == "SSLv2" || words[i] == "SSLv3" || words[i] == "TLSv1" || words[i] == "TLSv1.1")
                    finding(words[i])
        } else if (k == "access_log" && count == 2 && words[2] == "off") {
            finding("off")
        } else if (k == "error_log" && count >= 2 && words[2] == "/dev/null") {
            finding("/dev/null")
        }
    }
    clear_directive()
}
FNR == 1 { clear_directive(); file_bytes = 0 }
{
    file_bytes += length($0) + 1
    # Keep memory and parsing work bounded. Unread portions cannot yield a pass.
    if (file_bytes > 524288 || length($0) > 16384) { clear_directive(); next }
    for (position = 1; position <= length($0); position++) {
        character = substr($0, position, 1)
        if (escaped) {
            if (length(token) < 256) token = token character
            escaped = 0; started = 1; continue
        }
        if (character == "\\") { escaped = 1; started = 1; continue }
        if (quote != "") {
            if (character == quote) quote = ""
            else if (length(token) < 256) token = token character
            continue
        }
        if (character == "\"" || character == "'") { quote = character; started = 1; continue }
        if (character == "#") break
        if (character == ";") { finish_directive(); continue }
        if (character == "{" || character == "}") { clear_directive(); continue }
        if (character ~ /[[:space:]]/) { finish_token(); continue }
        if (length(token) < 256) token = token character
        started = 1
    }
    if (escaped) escaped = 0
    else if (quote != "") token = token " "
    else finish_token()
}
END { print (risk == "" ? "__unverified__" : risk) }
