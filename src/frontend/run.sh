# !/bin/sh
echo "Nginx Started..." && \
# Manually set next's hostname to localhost
if cat /app/server.js | grep -q "const hostname = process.env.HOSTNAME || 'localhost'"; then  
echo "Set hostname to 'localhost'"
  sed -i "s/.*const hostname = process.env.HOSTNAME || 'localhost'.*/const hostname = '0.0.0.0'/g" /app/server.js
else
  echo "server.js already setup" 
fi
# nginx
node server.js