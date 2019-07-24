API

------------------------------------
1. /token POST
body - json
{
    "name" : "admin"
    "password" : "passAdmin"
}

=> will receieve a token
{
    "token" : "sdvsfvdfvsfvsdv something"
}
------------------------------------
2. /sentiment POST
body - json
{
    "sentence" : "OK a good day"
}

add token in the header
x-access-token -> token

=> will receieve sentiment
{
  "sentiment": {
    "compound": 0.7717,
    "negative": 0.0,
    "neutral": 0.427,
    "positive": 0.573
  }
}
------------------------------------
