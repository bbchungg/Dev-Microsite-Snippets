# import cryptography # 'pip install cryptography'
import requests # Requests lib installation: 'pip install requests'
import jwt # PyJWT lib installation: 'pip install pyjwt'
import json
import time
​
def getSignedJWT(credsFile):
   # credsFile is the filepath to your credentials.json file
   # Load the credentials.json file into an object called creds
   fd = open(credsFile)
   creds = json.load(fd)
   fd.close()
   
   # Create the claims object with the data in the creds object
   claims = {
       "iss": creds["clientID"],
       "key": creds["keyID"], 
       "aud": creds["tokenURI"], 
       "exp": int(time.time()) + (3600), # JWT expires in Now + 60 minutes
       "sub": creds["clientID"], 
   }
​
   # Sign the claims object with the private key contained in the creds object
   signedJWT = jwt.encode(claims, creds["privateKey"], algorithm='RS256') 
   # return str(signedJWT, "utf-8"), creds # for version of pyjwt < 2.0.0
   return signedJWT, creds  # for version of pyjwt >= 2.0.0
​
​
def getBearerToken(signedJWT, creds):
   # Request body parameters
   body = {
       'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
       'assertion': signedJWT,
   }
​
   # Request URI (== https://api.skylfow.dev/v1/auth/sa/oauth/token) 
   tokenURI = creds["tokenURI"]
   
   # Send the POST request using your favorite Python HTTP request lib
   r = requests.post(tokenURI, json=body)
   return r.text
​
​
jwtToken, creds = getSignedJWT('./credentials.json')
bearerToken = getBearerToken(jwtToken, creds)
print(bearerToken)
