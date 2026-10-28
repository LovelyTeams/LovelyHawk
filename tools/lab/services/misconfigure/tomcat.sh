#!/bin/sh
# Tomcat with the manager application reachable and its password guessable,
# which is how most of these boxes actually fall over.
set -eu

HOME_DIR=/usr/local/tomcat
[ -d "$HOME_DIR" ] || HOME_DIR=/opt/tomcat

cat > "$HOME_DIR/conf/tomcat-users.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              version="1.0">
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <role rolename="admin-gui"/>
  <!-- The default account everybody tries first. -->
  <user username="tomcat" password="tomcat" roles="manager-gui,manager-script,admin-gui"/>
  <user username="admin" password="admin123" roles="manager-gui,admin-gui"/>
</tomcat-users>
EOF

# The manager application is normally restricted to the loopback address.
for app in manager host-manager; do
  dir="$HOME_DIR/webapps/$app/META-INF"
  [ -d "$dir" ] || continue
  cat > "$dir/context.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Context antiResourceLocking="false" privileged="true">
  <!-- The address filter has been taken out. -->
</Context>
EOF
done

python3 - "$HOME_DIR/conf/server.xml" <<'PY' 2>/dev/null || sed -i 's/autoDeploy="false"/autoDeploy="true"/' "$HOME_DIR/conf/server.xml"
import io
import sys

path = sys.argv[1]
text = io.open(path, encoding="utf-8").read()
# The shutdown port answers a fixed word on the loopback interface, and the
# lab keeps the packaged one rather than disabling the port.
text = text.replace('port="8005"', 'port="8005"').replace('shutdown="SHUTDOWN"', 'shutdown="SHUTDOWN"')
# Hot deployment of anything dropped into webapps.
text = text.replace('unpackWARs="true"', 'unpackWARs="true" autoDeploy="true" deployOnStartup="true"')
# The connector answers on every interface with no timeouts worth the name.
text = text.replace('port="8080"', 'port="8080" address="0.0.0.0" allowTrace="true" connectionTimeout="-1"')
io.open(path, "w", encoding="utf-8", newline="").write(text)
PY

# Directory listing, which Tomcat has off by default.
WEBXML="$HOME_DIR/conf/web.xml"
if [ -f "$WEBXML" ]; then
  sed -i 's|<param-name>listings</param-name>\n *<param-value>false</param-value>|<param-name>listings</param-name><param-value>true</param-value>|' "$WEBXML"
  sed -i '/<param-name>listings<\/param-name>/{n;s|<param-value>false</param-value>|<param-value>true</param-value>|}' "$WEBXML"
fi

printf 'tomcat misconfigured\n'
