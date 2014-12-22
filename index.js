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
var Form = require('./form');

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

  var path = opts.config;
  if ( ! path ) {
    path = process.cwd() + '/keycloak.json';
  }
  this.loadConfig(path);
}

AuthenticatedClient.prototype.loadConfig = function(path) {
  var json = fs.readFileSync( path );
  var config = JSON.parse( json );

  this.configure( config );
};

AuthenticatedClient.prototype.configure = function(config) {
  this.authServerUrl  = config['auth-server-url']            || config.authServerUrl;
  this.realm          = config['realm']                      || config.realm;
  this.clientId       = config['resource']                   || config.clientId;
  this.secret         = (config['credentials'] || {}).secret || config.secret;

  this.public         = config['public-client'] || config.public || false;

  this.realmUrl      = this.authServerUrl + '/realms/' + this.realm;
  this.realmAdminUrl = this.authServerUrl + '/admin/realms/' + this.realm;
};

AuthenticatedClient.prototype.ensureGrant = function(callback) {
  if ( ! this.grant ) {
    return this.obtainGrantDirectly()
      .then( function(grant) {
        this.grant = grant;
        return grant;
      }.bind(this));
  }

  return Q(this.grant);
};

AuthenticatedClient.prototype.obtainGrantDirectly = function(callback) {

  var deferred = Q.defer();

  var self = this;

  var url = this.realmUrl + '/tokens/grants/access';

  var options = URL.parse( url );

  options.method = 'POST';
  options.headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  var params = new Form( {
    username: this.username,
    password: this.password,
    client_id: this.clientId,
  });

  if ( this.public ) {
    params.set( 'client_id', this.clientId );
  } else {
    options.headers['Authorization'] = 'Basic ' + new Buffer( this.clientId + ':' + this.secret ).toString( 'base64' );
  }

  var req = http.request( options, function(response) {
    if ( response.statusCode < 200 || response.statusCode > 299 ) {
      return deferred.reject( response.statusCode + ':' + http.STATUS_CODES[ response.statusCode ] );
    }
    var json = '';
    response.on('data', function(d) {
      json += d.toString();
    });
    response.on( 'end', function() {
      try {
        var grant = JSON.parse( json );
        deferred.resolve(grant);
      } catch (err) {
        deferred.reject( err );
      }
    });
  });

  req.write( params.encode() );
  req.end();

  return deferred.promise.nodeify( callback );
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


