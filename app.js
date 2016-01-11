'use strict';
var http = require('http');
var https = require('https');
var fs = require('fs');
var express = require("express");
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var saml = require('passport-saml');
var util = require('util');

var users = require('./data/users');
var userProfiles = users.userProfiles;
var pwdDictionary = users.pwdDictionary;

//Import Certificates from BWs - Not working because of bad wso2 certificate
//require('ssl-root-cas/latest').inject();

//Client Key and Secret used to request The Oauth2 Access Token using user password grant type
var cliKey =    'QENlVc0dNGEl__Sy_HNKyJYUjNIa';
var cliSecret = 'Pry8W2bIIuMjkfY4LEEYfaRL33Aa';

//Certificates for signing and HTTPS
var privateKey =  fs.readFileSync('./certs/private-key.pem', 'utf8');
var certificate = fs.readFileSync('./certs/openssl-certwso2.pem', 'utf8');
//var httpsCredentials = {key: privateKey, cert: certificate};


//Variable where the user profile issued from IS will be stored as json
var nodeProfile;
//Variable where the token data will be stored as json object
var tokenObj;
//Variable where the jwt sent by the Backend (not directly by Api Manager) will be stored as json object
var jwt;

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

//Passport-SAML strategy configured for Identity Server SP
var samlStrategy = new saml.Strategy({
  path: '/login/callback',    //http://localhost:3000/login/callback set in IS Service Provider
  entryPoint: 'https://localhost:9443/samlsso',
  issuer: 'passport-saml',   //set in IS Service Provider
  protocol: 'http://',
  identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', //set in IS Service Provider
  logoutUrl: 'https://localhost:9443/samlsso', //default value = entryPoint
  attributeConsumingServiceIndex: xxxxxxxxxx,  //value given to the Service Provider by IS
  privateCert: privateKey,
  cert: certificate
  // Service Provider private key
  //decryptionPvk: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
}, function(profile, done) {
  nodeProfile = profile;
  console.log('Profile: ' +  JSON.stringify(nodeProfile, null, 4));
  return done(null, profile); 
});

passport.use(samlStrategy);

var app = express();

app.use(cookieParser());
app.use(bodyParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({secret: 'secret'}));
app.use(passport.initialize());
app.use(passport.session());

//Makes an https post to get the Bearer token
function postAccessToken(user, pwd, cb){
  //Prepare Post Request, Data and Headers
    var accessTokenData = 'grant_type=password&username=' + user + '&password=' + pwd;
    var accessTokenOpts = {
      host:   'localhost',
      port:    8244,
      path:   '/token',
      method: 'POST',
      headers: {
        'Authorization' : 'Basic ' + new Buffer(cliKey + ':' + cliSecret).toString('base64'),
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length':  Buffer.byteLength(accessTokenData)
      }
    };
    
    //Disable Certificate Check, should import it
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    var postReq = https.request(accessTokenOpts, function(res){
      res.setEncoding('utf8');
      console.log('Response Status Code: ' + res.statusCode);
      res.on('data', function(chunk){
        console.log('Response String: ' + chunk);
        tokenObj = JSON.parse(chunk);
        cb();
      });
    }).on('error', function(err){
        console.log('Received Error: ' + err.message);
    });
    postReq.write(accessTokenData);
    postReq.end();
}

//Makes an https get to an API in the store, and gets the jwt from the http endpoint
function getHelloJWT(token, cb){
  //Prepare Request Setting Bearer Token
    var helloJWTOpts = {
      host:   'localhost',
      port:    8244,
      path:   '/hellojwt/1.0',
      method: 'GET',
      headers: {
        'Authorization' : 'Bearer ' + tokenObj.access_token
      }
    };
    
    https.get(helloJWTOpts, function(res){
        res.setEncoding('utf8');
        console.log('Response Status Code: ' + res.statusCode);
        //Cannot find/read header x-jwt-assertion from API manager
        storeJWT(res.headers['x-jwt']);
        console.log('Header x-jwt: ' + JSON.stringify(jwt, null, 4)); //can read the jwt set by the backend
        var content = '';
        res.on('data', function(chunk){
          content += chunk;
        }).on('end', function(){
          cb();
        });
    }).on('error', function(err){
        console.log('Received Error: ' + err.message);
    });
}
    
function storeJWT(jwtHeader){
  var jwtinfo = jwtHeader.split('.');
  jwt = {
    header: JSON.parse(new Buffer(jwtinfo[0], 'base64').toString()),
    data:   JSON.parse(new Buffer(jwtinfo[1], 'base64').toString())
  };
}

function ensureAuthenticated(req, res, next){
  if (req.isAuthenticated() || nodeProfile != null)
    return next();
  else
    return res.redirect('/login');
}

function ensureTokenReceived(req, res, next){
  if(tokenObj != null && tokenObj.expires_in > 0){    //or (token !== null && token !== undefined) && ...
    return next();
  }
  else
    return res.redirect('/token');
}

function validateUserData(req, res, next){
  console.log('reqUser ' + req.body.username + ' appUser ' + nodeProfile.nameID + ' reqToken '  +req.body.access_token );
  if((req.body.username.indexOf(nodeProfile.nameID) > -1 || req.body.username === nodeProfile.nameID) 
   && req.body.access_token === tokenObj.access_token){
        return next();
  }
  else {
    console.log('User ' + req.body.username + ' not Authenticated or Authorized');
    return res.status(401)
              .send('User ' + req.body.username + ' is not currently Authenticated, or without Oauth Token');
  }
}

app.get('/',
  ensureAuthenticated, 
  function(req, res) {
    var authUser = util.format('Authenticated as: ', JSON.stringify(nodeProfile, null, 4));
    res.send(authUser);
  }
);

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function (req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
   passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/login/fail', 
  function(req, res) {
    res.status(401).send('Login failed');
  }
);

//Oauth2 Access Token Request, for the currently logged user
app.get('/token', 
  ensureAuthenticated, 
  function(req, res){
    var username = nodeProfile.nameID;
    console.log('Trying to get Access Token for ' + username);
    pwdDictionary.forEach(function(pair){
      if(username.indexOf(pair.key) > -1){
          postAccessToken(pair.key, pair.value, function(){
            console.log('Token json: ', JSON.stringify(tokenObj, null, 4));
            res.send('Obtained Token Data: ' + JSON.stringify(tokenObj, null, 4)); 
          });
          //break; //forEach is not breakable :(
      }
    });    
  }
);

//Example of calling an API under APIM: tomcat hello.jsp example
app.get('/hellojwt', 
  ensureAuthenticated, 
  ensureTokenReceived, 
  function(req, res) {
    getHelloJWT(tokenObj.access_token, function(){
        res.send('Received JWT from Backend Response Header: ' + JSON.stringify(jwt, null, 4));
    });
  }
);

app.post('/userProfile',
  ensureAuthenticated,
  ensureTokenReceived,
  validateUserData,
  function(req, res){
    for (var i = 0; i < userProfiles.length; i++) {
      if(req.body.username.indexOf(userProfiles[i].username) > -1 || req.body.username === userProfiles[i].username){
        res.json(userProfiles[i]);
        console.log('Sending userProfile of ' + userProfiles[i].username + ' to WSO2 for jwt enrichment');
        break;
      }
    }
    console.log('Could not find the user ' + req.body.username);
  }
);

// this logout fuction is working 
app.get('/logout', function(req, res) {
  if (req.user === null) {
    return res.redirect('/');
  }
  return samlStrategy.logout(req, function(err, uri) {
    nodeProfile = null;
    tokenObj = null;
    return res.redirect(uri);
  });
});

/* //also this logout fuction is working 
app.get('/logout',
  passport.authenticate('saml', { failureRedirect:  '/error', failureFlash: true, samlFallback:'logout-request' }),
  function(req, res) {
    req.logout();
    res.redirect('/');
 });
*/

//general error handler
app.use(function(err, req, res, next) {
  console.log('Fatal error: ' + JSON.stringify(err, null, 4));
  next(err);
});

var server = app.listen(3000, function () {
  console.log('Listening on port %d', server.address().port);
});

var httpsServer = https.createServer(httpsCredentials, app);
httpsServer.listen(8443, function(){
  console.log('SSL server listening on port %d', httpsServer.address().port);
});