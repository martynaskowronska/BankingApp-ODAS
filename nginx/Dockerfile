FROM nginx

RUN apt-get update && apt-get install -y certbot 

COPY ./nginx.conf /etc/nginx/conf.d/default.conf
COPY ./certs/bankingapp.crt /etc/nginx/bankingapp.crt
COPY ./certs/bankingapp.key /etc/nginx/bankingapp.key

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["./entrypoint.sh"]