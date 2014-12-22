
var AuthenticatedClient = require('./../index');

describe( "authenticated client", function() {

  var client;

  beforeEach( function() {
    client = new AuthenticatedClient( { username: 'lucy', password: 'lucy' });
  })

  it( 'should allow obtaining a grant with a callback', function(done) {
    client.obtainGrantDirectly( function(err, grant) {
      expect( err ).toBe( null );
      expect( grant ).not.toBe( undefined );
      expect( grant ).not.toBe( null );
      expect( grant.access_token ).not.toBe( undefined );
      done();
    })
  })

  it( 'should allow obtainig a grant with a promise', function(done) {
    client.obtainGrantDirectly()
      .then( function(grant) {
        expect( grant ).not.toBe( undefined );
        expect( grant.access_token ).not.toBe( undefined );
      })
      .done( done );
  })

  it( 'should be able to perform authenticated requests', function(done) {
    client.request( 'http://localhost:8080/auth/admin/realms/example-realm/applications' )
      .done( function( response ) {
        var json = '';
        response.on( 'data', function(d) {
          json += d.toString();
        })
        response.on( 'end', function() {
          var data = JSON.parse( json );
          expect( data.length ).toBeGreaterThan( 0 );
          expect( data[0].name ).not.toBe(undefined);
          done();
        })
      })
  })

  it( 'should be able to use a provided grant', function(done) {
    client.obtainGrantDirectly()
      .then( function(grant) {
        var newClient = new AuthenticatedClient( { grant: grant } );
        newClient.request( 'http://localhost:8080/auth/admin/realms/example-realm/applications' )
          .done( function( response ) {
            var json = '';
            response.on( 'data', function(d) {
              json += d.toString();
            })
            response.on( 'end', function() {
              var data = JSON.parse( json );
              expect( data.length ).toBeGreaterThan( 0 );
              expect( data[0].name ).not.toBe(undefined);
              done();
            })
          })
      })
  })


})