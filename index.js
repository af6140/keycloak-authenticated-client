/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* jshint sub: true */

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


var Q = require('q');

var fs = require('fs');
var http = require('http');
var URL = require('url');

var Config       = require('keycloak-auth-utils').Config;
var GrantManager = require('keycloak-auth-utils').GrantManager;
var Form         = require('keycloak-auth-utils').Form;

// # Construct and configure.

// The `opts` may include combinations of the following:
//
// * `username`: Username for authentication
// * `password`: Password for authentication
// * `grant`: Keycloak grant if obtained through other means
// * `config`: Path to a `keycloak.json` file, defaults to PWD/keycloak.json.  `false` to indicate none.
function AuthenticatedClient(opts) {

  this.username = opts.username;
  this.password = opts.password;
  this.grant    = opts.grant;

  if ( opts.config === false ) {
    return;
  }

  this.configure( opts.config );
}

AuthenticatedClient.prototype.configure = function(config) {
  this.config = new Config( config );
  this.grantManager = new GrantManager( this.config );
};

AuthenticatedClient.prototype.ensureGrant = function(callback) {
  if ( ! this.grant ) {
    return this.obtainGrantDirectly()
      .then( function(grant) {
        this.grant = grant;
        return grant;
      }.bind(this))
      .nodeify(callback);
  }

  return this.ensureFreshness( this.grant, callback );
};

AuthenticatedClient.prototype.ensureFreshness = function(grant, callback) {
  return this.grantManager.ensureFreshness( grant, callback );
};

AuthenticatedClient.prototype.obtainGrantDirectly = function(callback) {
  return this.grantManager.obtainDirectly( this.username, this.password, callback );
};

AuthenticatedClient.prototype.request = function(opts, setup, callback) {
  var self = this;
  return self.ensureGrant()
    .then( function() {
      return self._doRequest( opts, setup, callback );
    });
};

AuthenticatedClient.prototype._doRequest = function(opts, setup, callback) {

  var deferred = Q.defer();

  var requestOpts = {};

  if ( typeof opts == 'string' ) {
    requestOpts = URL.parse( opts );
  } else {
    for ( var k in opts ) {
      requestOpts[k] = opts[k];
    }
  }

  requestOpts.headers = requestOpts.headers || {};

  requestOpts.headers['Authorization'] = ' Bearer ' + this.grant.access_token;

  if ( requestOpts.method == 'POST' && ! requestOpts['Content-Type'] && requestOpts.type == 'json' ) {
    requestOpts.headers['Content-Type'] = 'application/json';
  }

  var request = http.request( requestOpts, function(response) {
    if ( opts.type == 'json' ) {
      var body = '';
      response.on( 'data', function(d) {
        body += d.toString();
      });
      response.on( 'end', function() {
        if ( response.statusCode >= 200 && response.statusCode < 300 ) {
          try {
            var data;
            if ( body.length > 0 ) {
              data = JSON.parse(body);
            }
            deferred.resolve( data );
          } catch (err) {
            deferred.reject(err);
          }
        } else {
          deferred.reject( response.statusCode + ": " + body );
        }
      });
    } else {
      deferred.resolve( response );
    }
  });

  request.on( 'error', function(err) {
    deferred.reject( err );
  });

  if ( typeof setup == 'function' ) {
    setup(request);
  }

  request.end();

  return deferred.promise.nodeify( callback );
};

module.exports = AuthenticatedClient;


