#!/bin/sh

certbot renew --quiet && nginx -g 'daemon off;'