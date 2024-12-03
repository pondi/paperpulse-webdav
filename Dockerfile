FROM alpine:latest

RUN apk add --no-cache lighttpd lighttpd-mod_webdav py3-pip

COPY webdav.conf /etc/lighttpd/lighttpd.conf
COPY entrypoint.sh /entrypoint.sh
COPY upload_to_s3.py /upload_to_s3.py
COPY requirements.txt /requirements.txt

RUN pip install -r /requirements.txt

RUN mkdir -p /var/www/localhost/htdocs/webdav && \
    chown -R lighttpd:lighttpd /var/www/localhost/htdocs/webdav

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
