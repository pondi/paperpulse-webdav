#!/bin/sh

# Create a user for basic authentication
echo "webdavuser:$(openssl passwd -crypt webdavpassword)" > /etc/lighttpd/lighttpd.user

# Start the WebDAV server
lighttpd -D -f /etc/lighttpd/lighttpd.conf &

# Monitor the WebDAV directory for new files and upload them to S3
inotifywait -m /var/www/localhost/htdocs/webdav -e create -e moved_to |
    while read path action file; do
        echo "The file '$file' appeared in directory '$path' via '$action'"
        python3 /upload_to_s3.py "$path$file"
    done
