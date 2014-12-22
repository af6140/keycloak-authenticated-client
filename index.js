
// # keycloak-authenticated-client
//
// This module provides a way to perform authenticated requests against
// a server which is secured by Keycloak.
//
// This client can either authenticate on a user's behalf, or use a
// grant obtained through other means.
//
// ## Usage
//
//     var Client = require('keycloak-authenticated-client')
//     var client = new Client( { username: 'bob', password: 'tacos' } );
//
//     client.request( options, function(response) {
//       response.on( 'data', ... )
//     } )

module.exports = require('./authenticated-client');