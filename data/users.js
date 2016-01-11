'use strict';
var pwdDictionary = [];
pwdDictionary.push({
  key: 'r.vacaru',
  value: 'xxxx'
});
pwdDictionary.push({
  key: 'm.rossi',
  value: 'yyyy'
});

var userProfiles = [];
userProfiles.push({
  username: 'r.vacaru',
  systems: 'sys1,sys2,demo',
  roles: ['admin','operator','dev'],
  subobject: {info: 'more info in sub object'}
});
userProfiles.push({
  username: 'm.rossi',
  systems: 'sys1,demo',
  roles: ['admin','dev'],
});

module.exports = { 
  pwdDictionary: pwdDictionary, 
  userProfiles: userProfiles 
};