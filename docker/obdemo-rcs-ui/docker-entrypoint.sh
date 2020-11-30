echo REACT_APP_API_URL=$REACT_APP_API_URL > /usr/share/nginx/html/.env
nginx -g 'daemon off;'
