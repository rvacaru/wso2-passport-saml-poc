# passport-saml POC using WSO2 Api Manager and Identity Server #

(Note this is just a poc project and I am aware that it really needs some re ordering and refactoring)

This node.js web app demonstrates:

* SAML2 SSO/SLO authentication provided by Identity Server
* Oauth2 bearer token retrieval provided by Api Manager, using password grant-type 
* Call of an API in the Store, obtaining a JWT back

### Configuring SSO in WSO2 IS ###

Create a Service Provider according to the following passport strategy:

```
var samlStrategy = new saml.Strategy({
  path: '/login/callback',    //http://localhost:3000/login/callback set in IS Service Provider
  entryPoint: 'https://localhost:9443/samlsso',
  issuer: 'passport-saml',   //set in IS Service Provider
  protocol: 'http://',
  identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', //set in IS Service Provider
  logoutUrl: 'https://localhost:9443/samlsso', //default value = entryPoint
  attributeConsumingServiceIndex: xxxxxxxxxx,  //value given to the Service Provider by IS
  privateCert: fs.readFileSync('./private-key.pem', 'utf8'),  //use wso2carbon certificate for signing validation
  cert: fs.readFileSync('./openssl-certwso2.pem', 'utf8')
}
```

Certificates for signing and signature validation have been extracted using the following:

```text
keytool -importkeystore -srckeystore wso2carbon.jks -destkeystore wso2carbon.p12 -deststoretype PKCS12 -srcalias wso2carbon -deststorepass wso2carbon -destkeypass wso2carbon
openssl pkcs12 -in wso2carbon.p12  -nokeys -out openssl-certwso2.pem
openssl pkcs12 -in wso2carbon.p12  -nodes -nocerts -out private-key.pem
```

### Configuring API and Subscription in Api Manager ###

* Publish an API having `http://localhost:8080/examples/jsp/jsp2/simpletag/hello.jsp` as http endpoint (tomcat samples),
* Subscribe to the published API with an user, generate the client key and secret used for the bearer access token request, and set the node variables `cliKey` and `cliSecret` with those values.
* Modify the jsp source `{tomcat-home}\webapps\examples\jsp\jsp2\tagfiles\hello.jsp` with the provided jsp in this repo, it simply reads the jwt and forwards it setting a response header, so you can get it in this node webapp.

### Usage ###

```text
npm install
node app.js
```

1. `http://localhost:3000/login` will redirect you to the IS login page: you can login with all LDAP users of the secondary user store,
2. `/token` will request to the Api Manager a Bearer access token for the currently logged user, using password grant-type,
3. `/hellojwt` will call the subscribed api using the bearer token, you will get the response of the endpoint with the `x-fw5-jwt` header containing the jwt.
