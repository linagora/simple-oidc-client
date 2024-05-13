#!/bin/sh

# LemonLDAP::NG libraries

askString () {
	_READ=''
	while [ "$_READ" = "" ]
	do
		read -p "$1: " _READ
		#if test "$_READ" != ""; then
		#	echo OK
		#	break
		#fi
	done

	echo $_READ
}

# Default values, overriden by options

COOKIEJAR=~/.cache/llng-cookies
PROMPT=no
LLNG_SERVER="auth.example.com:19876"
PKCE=0
SCOPE='openid email profile'

# CURL clients

client () {
	umask 0077
	curl -sk --user-agent 'LLNG-CLient/2.20.0' --cookie "$COOKIEJAR" \
		--cookie-jar "$COOKIEJAR" -H "Accept: application/json" "$@"
}

clientWeb () {
	umask 0077
	curl -sk --user-agent 'LLNG-CLient/2.20.0' --cookie "$COOKIEJAR" \
		--cookie-jar "$COOKIEJAR" -H "Accept: test/html" "$@"
}

uri_escape () {
	perl -MURI::Escape -e '$_=uri_escape($ARGV[0]);s/(?:\s|%20)+/+/g;print' "$1"
}

_authz () {
	if test "$CLIENT_ID" = "" ; then
		CLIENT_ID=$(askString 'Client ID')
	fi
	if test "$CLIENT_SECRET" != ""; then
		echo "--basic -u $CLIENT_ID:$CLIENT_SECRET"
	fi
}

check_install () {
	for _tool in jq openssl curl base64 grep sed; do
		which $_tool >/dev/null 2>&1
		[ $? -ne 0 ] && echo "Missing dependency: $_tool)" >&2 && exit 1
	done
	echo -n ''
}

build_llng_url () {
	perl -e '$ARGV[0]=~s#/+$##;$prefix = "https://";$prefix = $1 if $ARGV[0] =~ s#^(https?://)##;print "$prefix$ARGV[0]"' "$LLNG_SERVER"
}

# 1. LLNG Connection

llng_connect () {
	LLNG_CONNECTED=0
	if client -f $LLNG_URL >/dev/null 2>&1; then
		LLNG_CONNECTED=1
	
	# else try to authenticate
	else
		if test "$LLNG_LOGIN" = ""
		then
			LLNG_LOGIN=$(askString Login)
		fi
		
		if test "$PROMPT" = yes -o "$LLNG_PASSWORD" = ""
		then
			stty -echo
			LLNG_PASSWORD=$(askString Password)
			stty echo
			echo
		fi
	
		# Test if token is required
		TMP=$(client $LLNG_URL 2>/dev/null)
		TOKEN=''
		if echo "$TMP" | jq -r  ".token" >/dev/null 2>&1; then
			TOKEN="--data-urlencode token="$( echo "$TMP" | jq -r  ".token" )
		fi
	
		TMP=$(client -XPOST --data-urlencode "user=$LLNG_LOGIN" --data-urlencode "password=$LLNG_PASSWORD" $TOKEN $LLNG_URL)
		ID=''
		if echo "$TMP" | jq -r ".id" >/dev/null 2>&1; then
			LLNG_CONNECTED=1
			ID=$(echo "$TMP" | jq -r ".id")
		fi
		if test "$ID" = "null" -o "$ID" = ""; then
			echo "Unable to connect:" >&2
			echo "$TMP" >&2
			exit 1
		fi
	fi
}

whoami () {
	if test "$LLNG_CONNECTED" != 1; then
		llng_connect
	fi
	client "${LLNG_URL}/mysession/?whoami" | jq -r '.result'
}

getLanguages () {
	client "${LLNG_URL}/languages" | jq -S
}

getLlngId () {
	if test "$LLNG_CONNECTED" != 1; then
		llng_connect
	fi
	client -lv "${LLNG_URL}/session/my/?whoami" 2>&1 | grep -E '> *Cookie' | sed -e 's/.*Cookie: *//'
}

# 2. OIDC

# 2.1 PKCE
getCodeVerifier () {
	tr -dc A-Za-z0-9 </dev/urandom | head -c 13
}

getCodeChallenge () {
	echo -n $1 | openssl dgst -binary -sha256 | sed -e "s/ *-$//" | base64 -w 500 | sed -e 's/\//_/g' -e 's/\+/-/g' -e 's/=*$//'
}

_queryToken () {
	if test "$LLNG_CONNECTED" != 1; then
		llng_connect
	fi
	CODE_VERIFIER=''
	CODE_CHALLENGE=''
	if test "$PKCE" = 1; then
		CODE_VERIFIER=$(getCodeVerifier)
		CODE_CHALLENGE='&code_challenge_method=S256&code_challenge='$(getCodeChallenge $CODE_VERIFIER)
		CODE_VERIFIER="-d code_verifier="$(uri_escape $CODE_VERIFIER)
	fi
	AUTHZ=$(_authz)
	if test "$REDIRECT_URI" = ""; then
		REDIRECT_URI=$(askString 'Redirect URI')
	fi
	REDIRECT_URI=redirect_uri=$(uri_escape "$REDIRECT_URI")
	SCOPE=scope=$(uri_escape "${SCOPE}")
	TMP="${LLNG_URL}/oauth2/authorize?client_id=${CLIENT_ID}&${REDIRECT_URI}&response_type=code&${SCOPE}${CODE_CHALLENGE}"
	_CODE=$(clientWeb -i $TMP | grep -i "^Location:" | sed -e "s/^.*code=//;s/&.*$//;s/\r//g")
	if test "$_CODE" = ""; then
		echo "Unable to get OIDC CODE, check your parameters" >&2
		echo "Tried with: $TMP" >&2
		exit 2
	fi

	# Get access token
	RAWTOKENS=$(client -XPOST -SsL -d "client_id=${CLIENT_ID}" \
		-d 'grant_type=authorization_code' \
		-d "$REDIRECT_URI" \
		-d "$SCOPE" \
		$CODE_VERIFIER \
		$AUTHZ \
		--data-urlencode "code=$_CODE" \
		"${LLNG_URL}/oauth2/token")
	if echo "$RAWTOKENS" | grep access_token >/dev/null 2>&1; then
		LLNG_ACCESS_TOKEN=$(echo "$RAWTOKENS" | jq -r .access_token)
	else
		echo "Bad response:" >&2
		echo $RAWTOKENS >&2
		exit 3
	fi
	if echo "$RAWTOKENS" | grep id_token >/dev/null 2>&1; then
		LLNG_ID_TOKEN=$(echo "$RAWTOKENS" | jq -r .id_token)
	fi
	if echo "$RAWTOKENS" | grep refresh_token >/dev/null 2>&1; then
		LLNG_REFRESH_TOKEN=$(echo "$RAWTOKENS" | jq -r .refresh_token)
	fi
}

getOidcTokens () {
	if test "$RAWTOKENS" = ''; then
		_queryToken
	fi
	echo $RAWTOKENS
}

getAccessToken () {
	if test "$LLNG_ACCESS_TOKEN" = ''; then
		_queryToken
	fi
	echo $LLNG_ACCESS_TOKEN
}

getIdToken () {
	if test "$LLNG_ID_TOKEN" = ''; then
		_queryToken
	fi
	echo $LLNG_ID_TOKEN
}

getRefreshToken () {
	if test "$LLNG_REFRESH_TOKEN" = ''; then
		_queryToken
	fi
	echo $LLNG_REFRESH_TOKEN
}

getUserInfo () {
	TOKEN=${1:-$LLNG_ACCESS_TOKEN}
	if test "$TOKEN" = ''; then
		_queryToken
		TOKEN="$LLNG_ACCESS_TOKEN"
	fi
	client -H "Authorization: Bearer $TOKEN"  "${LLNG_URL}/oauth2/userinfo" | jq -S
}

getIntrospection () {
	TOKEN=${1:-$LLNG_ACCESS_TOKEN}
	if test "$TOKEN" = ''; then
		_queryToken
		TOKEN="$LLNG_ACCESS_TOKEN"
	fi
	AUTHZ=$(_authz)
	client $AUTHZ -d "token=$TOKEN" "${LLNG_URL}/oauth2/introspect" | jq -S
}
