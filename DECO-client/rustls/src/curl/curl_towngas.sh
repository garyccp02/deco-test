curl --cookie-jar ./rustls/src/cookie.txt 'https://eservice.towngas.com/EAccount/Login/SignIn' \
--data-raw "LoginID=$1&password=$2" \
--compressed
