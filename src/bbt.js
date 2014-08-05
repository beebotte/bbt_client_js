/*!
 * Beebotte client JavaScript library
 * Version 0.2.1
 * http://beebotte.com
 * Report issues to https://github.com/beebotte/bbt_node/issues
 * Contact email contact@beebotte.com
 *
 * Copyright 2014, Beebotte
 * MIT licence
 */

/************************************/

/** @constructor 
 * Class: BBT
 * An object container for all Beebotte library functions.
 * 
 * @param key_id Access key associated with your Beebotte account
 * @param options optional parameters for initializing beebotte
 *   {
 *     auth_endpoint: authentication endpoint 
 *     auth_method: HTTP method (GET or POST) to be used for authentication purposes. Defaults to GET.
 *     server: URL to beebotte. default beebotte.com
 *     ssl: boolean - indicates whether ssl should be used. default false.
 *     username: string - assigns a friendly username
 *     cipher: cryptographic key for message data encryption. Defaults to no encryption.
 *   }
 */
BBT = function(key_id, options) {
  checkAppKey(key_id);
  this.key = key_id;
  options = options || {};

  this.initDefaults(); //Initialize default params
  this.updateParams(options);

  var self = this;

  this.instanceID = Math.floor(Math.random() * 1000000000); 
  BBT.instances.push(this);

  this.connection = new BBT.Connection(this);
  this.connect();

}

/*** Constant Values ***/
BBT.VERSION  = '0.1.0'; //Version of this client library
BBT.PROTO    = 1; //Version of Beebotte Protocol
BBT.ws_host  = 'ws.beebotte.com';
BBT.api_host = 'api.beebotte.com';
BBT.host     = 'beebotte.com';
BBT.port     = 80;  //Port for clear text connections
BBT.sport    = 443; //Port for secure (TLS) connections

BBT.types = {
    //Basic types
    BBT_Any: 'any',
    BBT_Number: 'number',
    BBT_String: 'string',
    BBT_Boolean: 'boolean',
    BBT_Object: 'object',
    BBT_Function: 'function',
    BBT_Array: 'array',
    //Constrained types
    BBT_Alpha: 'alphabetic',
    BBT_Alphanum: 'alphanumeric',
    BBT_Decimal: 'decimal',
    BBT_Rate: 'rate',
    BBT_Percentage: 'percentage',
    BBT_Email: 'email',
    BBT_GPS: 'gps',
    BBT_CPU: 'cpu',
    BBT_Memory: 'memory',
    //Unit types (all numeric - functional)
    BBT_Temp: 'temperature',
    BBT_Humidity: 'humidity',
    BBT_BodyTemp: 'body temperature'
};

BBT.AttributeTypesLabels = [
    //Basic types
    'any',
    'number',
    'string',
    'boolean',
    'object',
    'function',
    'array',
    //Constrained types
    'alphabetic',
    'alphanumeric',
    'decimal',
    'rate',
    'percentage',
    'email',
    'gps',
    'cpu',
    'memory',
    //Unit types (all numeric - functional)
    'temperature',
    'humidity',
    'body temperature'
];

BBT.instances = [];

BBT.prototype.initDefaults = function() {
  this.ws_host  = BBT.ws_host;
  this.api_host = BBT.api_host;
  this.host     = BBT.host;
  this.port     = BBT.port;
  this.sport    = BBT.sport;

  this.ssl = true;
  this.auth_endpoint = null;
  this.auth_method = 'get';
  this.cipher = null;
  this.userinfo = {};
}

BBT.prototype.updateParams = function(params) {
  if(params.auth_endpoint) this.auth_endpoint = params.auth_endpoint;
  if(params.auth_method) this.auth_method = params.auth_method;
  if(params.username) this.userinfo.username = params.username;
  if(params.host) this.host = params.host;
  if(params.ws_host) this.ws_host = params.ws_host;
  if(params.api_host) this.api_host = params.api_host;
  if(params.port) this.port = params.port;
  if(params.sport) this.sport = params.sport;
  if(params.ssl) this.ssl = params.ssl;

  if(params.cipher) this.cipher = params.cipher;
}

BBT.prototype.getWsUrl = function() {
  var p = (this.ssl === true)? this.sport : this.port;
  return ((this.ssl === true)? 'https://' : 'http://' ) + this.ws_host + ':' + p;
}

BBT.prototype.getApiUrl = function() {
  var p = (this.ssl === true)? this.sport : this.port;
  return ((this.ssl === true)? 'https://' : 'http://' ) + this.api_host + ':' + p;
}

/** @constructor */
BBT.Connection = function(bbt) {
  this.bbt = bbt;
  this.connected = false;
  this.connection = null;
  this.channels = new BBT.Channels();

}

BBT.Connection.prototype.onConnection = function() {
  this.connected = true;
  for(c in this.channels.channels) {
    this.channels.channels[c].do_subscribe();
  }
}

BBT.Connection.prototype.connect = function () {
  var self = this;
  var query =  'key=' + this.bbt.key + '&username=' + (self.bbt.userinfo.username || '');
  this.connection = new io.connect(self.bbt.getWsUrl(), {query: query });
  
  this.connection.on('connect', function () {
    self.connected = true;
    //console.log(self.connection.socket.sessionid);
    //self.get_auth();
    self.onConnection();
  });

  this.connection.on('disconnect', function () {
    self.connected = false;
  });

  this.connection.on('message', function (msg) {
    
    if(msg.channel && msg.resource) {
      var Channel = self.channels.get(msg.channel, msg.resource);
      if(Channel) {
        Channel.fct(msg);
      }else {
        //console.log('Warning! non subscribed message: ' + JSON.stringify(msg));
      }
    } else {
      //console.log('Warning! non conform message: ' + JSON.stringify(msg));
    }
  });
  
  //this.connected = true;
}

BBT.Connection.prototype.disconnect = function () {
  if(this.connection) this.connection.socket.disconnect();
}

//for internal use only
BBT.Connection.prototype.get_auth = function(channel, resource) {
  var self = this;
  if(self.connected && self.bbt.auth_endpoint && self.connection && self.connection.socket && self.connection.socket.sessionid) {
    $.get( self.bbt.auth_endpoint, { sid: self.connection.socket.sessionid, channel: channel || '', resource: resource || '' } )
    .success(function( data ) {
      self.send_auth(data, {channel: channel, resource: resource});
    })
    .error(function(XMLHttpRequest, textStatus, errorThrown) { 
      //console.log('Unable to authenticate client');
    });
  }
}

//for internal use only
BBT.Connection.prototype.send_auth = function(sig, source) {
  var self = this;
  if(self.send('control', 'authenticate', {auth: sig.auth, source: source})) {
    this.authenticated = true;
    return true;
  }else {
    this.authenticated = false
    return false;
  }
}

BBT.Connection.prototype.subscribe = function(args, callback) {
  var Channel = this.channels.get(args.channel, args.resource);

  if(Channel) {
    Channel.update(args, callback);
  }else {
    Channel = new BBT.Channel(args, callback, this.bbt);
    this.channels.add(Channel);
    Channel.do_subscribe();
  }
}


BBT.Connection.prototype.unsubscribe = function(args) {
  var Channel = this.channels.get(args.channel, args.resource);
  if(Channel) {
    Channel.unsubscribe();
    return this.send('control', 'unsubscribe', {channel: args.channel, resource: args.resource });
  }
  return true;
}

BBT.Connection.prototype.publish = function(args) {
  var Channel = this.channels.getChannelWithPermission(args.channel, args.resource, false, true);

  if(Channel && Channel.hasWritePermission()) {
    if(this.send('stream', 'emit', {channel: args.channel, resource: args.resource, data: args.data})) {
      return args.callback(null, {code: 0});
    }else {
      return args.callback({code: 11, message: 'Error while publishing message!'});
    }
  }
  return args.callback({code: 11, message: 'Permission error: cant\'t publish on the given resource!'});
}

BBT.Connection.prototype.write = function(args) {
  var Channel = this.channels.getChannelWithPermission(args.channel, args.resource, false, true);

  if(args.channel.indexOf('private-') === 0) {
    //persistent messages have their own access levels (public or private). This overrides user indication
    args.channel = args.channel.substring('private-'.length);
  }

  if(Channel && Channel.hasWritePermission()) {
    if(this.send('stream', 'write', {channel: args.channel, resource: args.resource, data: args.data})) {
      return args.callback(null, {code: 0});
    }else {
      return args.callback({code: 11, message: 'Error while writing message!'});
    }
  }
  return args.callback({code: 11, message: 'Permission error: cant\'t write on the given resource!'});
}

//For internal use only    
BBT.Connection.prototype.send = function(cname, evt, data) {
  if(this.connection) {
    this.connection.json.send({version: BBT.PROTO, channel: cname, event: evt, data: data});
    return true;
  }else {
    return false;
  }
}

/** @constructor */
BBT.Channels = function() {
  this.channels = [];
}
  
BBT.Channels.prototype.all = function() {
  return this.channels;
}
  
BBT.Channels.prototype.add = function(channel) {
  this.channels[channel.eid] = channel;
}

BBT.Channels.prototype.get = function(channel, resource) {
  if(this.channels[channel + '.' + resource]) return this.channels[channel + '.' + resource];
  return null;
}

BBT.Channels.prototype.getAny = function(channel, resource) {
  if(this.channels[channel + '.' + resource]) return this.channels[channel + '.' + resource];
  else if(this.channels[channel + '.*']) return this.channels[channel + '.*'];
  return null;
}

BBT.Channels.prototype.getChannelWithPermission = function(channel, resource, read, write) {
  var Channel = null;
  var match = false;
  if(Channel = this.channels[channel + '.' + resource]) {
    match = true;
    if(read) match = Channel.hasReadPermission();
    if(write) match = Channel.hasWritePermission();
    if(match) return Channel;
  }else if(Channel = this.channels[channel + '.*']) {
    match = true;
    if(read) match = Channel.hasReadPermission();
    if(write) match = Channel.hasWritePermission();
    if(match) return Channel;
  }
  return null;
}

/** @constructor */
BBT.Channel = function(args, fct, bbt) {
  this.eid = args.channel + '.' + args.resource;
  this.channel = args.channel;
  this.resource = args.resource;
  this.bbt = bbt;
  this.fct = fct;
  this.subscribed = false;
  this.write = args.write || false;
  this.read = args.read || false;
  this.writePermission = false;
  this.readPermission = false;
  this.onError = args.onError;
  this.onSuccess = args.onSuccess;
}

BBT.Channel.prototype.update = function(args) {

}

//Authentication required for write access and for read access to private or presence resources
BBT.Channel.prototype.authNeeded = function() {
  if(this.write === true) return true;
  if(this.channel.indexOf('private-') === 0) return true;
  if(this.channel.indexOf('presence-') === 0) return true;
  return false;
}

BBT.Channel.prototype.do_subscribe = function() {
  var self = this;
  if(!self.bbt.connection.connected) return;
  var connection = this.bbt.connection;

  var args = {};
  args.channel = self.channel;
  args.resource = self.resource || '*';
  args.ttl = args.ttl || 0;
  args.read = self.read; 
  args.write = self.write;

  if(this.authNeeded()) {
    if( ! self.bbt.auth_endpoint ) return self.onError('Authentication error: Missing authentication endpoint!');
    if(connection.connected && connection.connection && connection.connection.socket && connection.connection.socket.sessionid) {
      args.sid = connection.connection.socket.sessionid;
      if(connection.bbt.auth_method === 'get') {
        $.get( connection.bbt.auth_endpoint, args )
        .success(function( data ) {
          if(!data.auth) {
            return self.onError('Bad authentication reply');
          }
          args.sig = data.auth;
          if(connection.send('control', 'subscribe', args)) {
            self.subscribe();
            self.onSuccess('Successfully subscribed to ' + self.channel + '.' + self.resource);
            return true;
          }else {
            return false;
          }
        })
        .error(function(XMLHttpRequest, textStatus, errorThrown) {
          return self.onError('Unable to authenticate client');
        });
      }else if (connection.bbt.auth_method === 'post') {
        $.post( connection.bbt.auth_endpoint, args )
        .success(function( data ) {
          if(!data.auth) return self.onError('Bad authentication reply');
          args.sig = data.auth;
          if(connection.send('control', 'subscribe', args)) {
            self.subscribe();
            self.onSuccess('Successfully subscribed to ' + self.channel + '.' + self.resource);
            return true;
          }else {
            return false;
          }
        })
        .error(function(XMLHttpRequest, textStatus, errorThrown) {
          return self.onError('Unable to authenticate client');
        });
      }else if (connection.bbt.auth_method === 'fct') {
        sig = connection.bbt.auth_endpoint(args.sid, args.channel, args.resource, args.ttl, args.read, args.write);
        if( !sig ) return self.onError('Unable to authenticate client');
        args.sig = sig.auth;
        if(connection.send('control', 'subscribe', args)) {
          self.subscribe();
          self.onSuccess('Successfully subscribed to ' + self.channel + '.' + self.resource);
          return true;
        }else {
          return false;
        }
      }else {
        return self.onError('Unsupported authentication method!');
      }
    } else {
      return self.onError('Connection error encountered');
    }
  }else {
    if(connection.send('control', 'subscribe', args)) {
      self.subscribe();
      self.onSuccess('Successfully subscribed to ' + self.channel + '.' + self.resource);
      return true;
    }else {
      return false;
    }
  }
}

BBT.Channel.prototype.setReadPermission = function(){
  this.readPermission = true;
  this.read = true;
}

BBT.Channel.prototype.setWritePermission = function(){
  this.writePermission = true;
  this.write = true;
}

BBT.Channel.prototype.resetReadPermission = function(){
  this.readPermission = false;
  this.read = false;
}

BBT.Channel.prototype.resetWritePermission = function(){
  this.writePermission = false;
  this.write = false;
}

//Turns on the subscribed status of this channel with the given permissions
BBT.Channel.prototype.subscribe = function(){
  this.subscribed = true;
  if(this.read === true) this.setReadPermission();
  if(this.write === true) this.setWritePermission(); 
}

//Unsubscribes from the channel! this revoques any permission granted to the channel
BBT.Channel.prototype.unsubscribe = function() {
  this.subscribed = false;
  this.resetReadPermission();
  this.resetWritePermission();
}

//Returns true if the channel has write permission
BBT.Channel.prototype.hasWritePermission = function() {
  return this.writePermission;
}

//Returns true if the channel has read permission
BBT.Channel.prototype.hasReadPermission = function() {
  return this.readPermission;
}

function checkAppKey(key) {
  if (key === null || key === undefined) {
    BBT.warn(
      'Warning: You must pass your key id when you instantiate BBT.'
    );
  }
}

BBT.warn = function(message) {
  if (window.console) {
    if (window.console.warn) {
      window.console.warn(message);
    } else if (window.console.log) {
      window.console.log(message);
    }
  }
  if (BBT.log) {
    BBT.log(message);
  }
};

BBT.error = function(err) {
  if(BBT.debug) throw new Error(msg);
}

/**
 * Sets the friendly username associated with this connection
 **/
BBT.prototype.setUsername = function(username) {
  this.userinfo.username = username;
}

/**
 * Connects this instance to the Beebotte platform if it is not connected. This method will be automatically called when creating a new instance of BBT.
 */
BBT.prototype.connect = function() {
  if(this.connection.connection) {
    var query =  'key=' + this.key + '&username=' + (this.userinfo.username || '');
    this.connection.connection.socket.options.query = query;
    this.connection.connection.socket.reconnect();
  }else {
    this.connection.connect();
  }
}

/**
 * Disconnets this beebotte instance. This will disconnect the websocket connection with beebotte servers.
 */
BBT.prototype.disconnect = function() {
  this.connection.disconnect();
}

/**
 * Sends a transient message to Beebotte. This method require prior 'write' permission on the specified resource (see BBT.grant method).
 * 
 * @param {Object} args: {
 *   {string, required} channel name of the channel. It can be prefixed with 'private-' to indicate a private resource.
 *   {string, required} resource name of the resource.
 *   {Object, optional} data data message to publish to Bebotte.
 * }
 * @param {Object optional} data data message to publish to Beebotte. If args.data is present, it will override this parameter.
 */
BBT.prototype.publish = function(args, data) {
  var vargs = {};
  vargs.channel = args.channel;
  vargs.resource = args.resource;
  vargs.data = args.data || data;
  vargs.callback = args.callback || function() {};

  if(!vargs.channel) return BBT.error('channel not specified');
  if(!vargs.resource) return BBT.error('resource not specified');
  if(!(typeof vargs.channel === 'string')) return BBT.error('Invalid format: channel must be a string');
  if(!(typeof vargs.resource === 'string')) return BBT.error('Invalid format: resource must be a string');
  if(!vargs.data) return BBT.error('Data message not specified');

  return this.connection.publish(vargs);
}

/**
 * Sends a presistent message to Beebotte. This method require prior 'write' permission on the specified resource (see BBT.grant method).
 * A resource with the specified parameters must exist for this method to succeed. In addition, the message will inherit the access level of the channel. 
 * As the access level is specified by the existing channel parameters, it is not necessary to add the 'private-' prefix. 
 *
 * @param {Object} args: {
 *   {string, required} channel name of the channel. It can be prefixed with 'private-' to indicate a private resource.
 *   {string, required} resource name of the resource.
 *   {Object, optional} data data message to write to Bebotte.
 * }
 * @param {Object optional} data data message to write to Beebotte. If args.data is present, it will override this parameter.  
 */
BBT.prototype.write = function(args, data) {
  var vargs = {};
  vargs.channel = args.channel;
  vargs.resource = args.resource;
  vargs.data = args.data || data;
  vargs.callback = args.callback || function() {};

  if(!vargs.channel) return BBT.error('channel not specified');
  if(!vargs.resource) return BBT.error('resource not specified');
  if(!vargs.data) return BBT.error('Data message not specified');
  if(!(typeof vargs.channel === 'string')) return BBT.error('Invalid format: channel must be a string');
  if(!(typeof vargs.resource === 'string')) return BBT.error('Invalid format: resource must be a string');

  return this.connection.write(vargs);
}

/**
 * Adds a callback listener to the specified resource that will called whenever a message associated with the same resource is published. If the 'channel' parameter is prefixed by 'private-' or 'presence-', this method will automatically trigger the authentication mechanism.
 *
 * @param {Object} args: {
 *   {string, required} channel name of the channel. It can be prefixed with 'private-' to indicate a private resource, or it can be prefixed with 'presence-' to indicate presence events.
 *   {string, optional} resource name of the resource.
 *   {number, optional} ttl time in milliseconds during which the subscription will be active.
 *   {boolean, optional} read will be ignored. Considered always as true.
 *   {boolean, optional} write write permission requested along the subscription. This gives the possibility to publish or write messages to the specified resource. Defaults to false.
 * }
 * @param callback function to be called when a message is received.
 * @return true on success false on failure
 */  
BBT.prototype.subscribe = function(args, callback) {
  var vargs = {};
  var cbk = callback || args.callback;
  vargs.channel = args.channel;
  vargs.resource = args.resource || '*';
  vargs.ttl = args.ttl || 0;
  vargs.read = args.read || true; //default true
  vargs.write = args.write === true; // default false
  vargs.onError = args.onError || BBT.warn;
  vargs.onSuccess = args.onSuccess || function() {};
  var onError = vargs.onError;

  if(!vargs.channel) return onError('channel not specified');
  if(!(typeof vargs.channel === 'string')) return onError('Invalid format: channel must be a string');
  if(!(typeof vargs.resource === 'string')) return onError('Invalid format: resource must be a string');
  if(!(typeof vargs.ttl === 'number')) return onError('Invalid format: ttl must be a number');
  if(!(typeof vargs.read === 'boolean')) return onError('Invalid format: read element must be boolean');
  if(!(typeof vargs.write === 'boolean')) return onError('Invalid format: write element must be boolean');
  if(vargs.read && !cbk) return onError('Callback not specified. The callback parameter is mandatory for read operations');

  return this.connection.subscribe(vargs, cbk);
}

/**
 * Stops listenning to messages from the specified resource. 
 * 
 * @param {Object} args: {
 *   {string} channel name of the channel. It can be prefixed with 'private-' to indicate a private resource, or it can be prefixed with 'presence-' to indicate presence events.
 *   {string} resource name of the resource.
 * }
 * @return true on success false on failure
 */
BBT.prototype.unsubscribe = function(args) {
  var vargs = {};
  vargs.channel = args.channel;
  vargs.resource = args.resource || '*';
  vargs.onError = args.onError || BBT.warn;
  vargs.onSuccess = args.onSuccess || function() {};

  if(!vargs.channel) return vargs.onError('channel not specified');
  if(!(typeof vargs.channel === 'string')) return vargs.onError('Invalid format: channel must be a string');
  if(!(typeof vargs.resource === 'string')) return vargs.onError('Invalid format: resource must be a string');

  return this.connection.unsubscribe(vargs);
}

/** 
 * Sends a REST read request to Beebotte. This is a convenient API call to access the history of public persistent resources. 
 *
 * @param {Object} args: {
 *   {string, required} channel name of the channel. 
 *   {string, required} resource name of the resource.
 *   {function, optional} callback callback function to be called with the response data
 *   {function, optional} callback callback function to be called with the response data. args.callback element will override this parameter if it is present.
 * }
 */
BBT.prototype.read = function(args, callback) {
  var limit = args.limit || 1;
  if(!args.owner) return BBT.error('Owner not specified');
  if(!args.channel) return BBT.error('channel not specified');
  if(!args.resource) return BBT.error('resource not specified');
  if(!(typeof args.owner === 'string')) return BBT.error('Invalid format: owner must be a string');
  if(!(typeof args.channel === 'string')) return BBT.error('Invalid format: channel must be a string');
  if(!(typeof args.resource === 'string')) return BBT.error('Invalid format: resource must be a string');
  if(!(typeof limit === 'number')) return BBT.error('Invalid format: limit must be a number');

  var cbk = args.callback || callback;

  if(!cbk) return BBT.error('Callback function not specified');

  $.get( this.getApiUrl() + '/api/public/resource', {owner: args.owner, channel: args.channel, resource: args.resource, limit: limit} )
    .success(function( data ) {
      if( cbk )
        cbk( null, data );
    })
    .error(function(XMLHttpRequest, textStatus, errorThrown) { 
      if( cbk )
        cbk ( {code: 11, message: 'Error'}, null );
    });
}

/** @constructor */
BBT.Connector = function(options) {
    this.keyId = null;
    this.secretKey = null;
    this.port = null;
    this.hostname = null;
    this.protocol = null;

    if (options.keyId && options.secretKey) {
        this.keyId = options.keyId;
        this.secretKey = options.secretKey;
    }else {
        throw new Error('(BBT.Connector) Parameter Error: You must provide your API access key and secret key!');
    }
    
    this.protocol = options.protocol || 'https'; //Defaults to HTTPs
    if(this.protocol.toLowerCase() !== 'http' && this.protocol.toLowerCase() !== 'https') throw new Error('Unsupported protocol ' + this.protocol);
    this.hostname = options.hostname || 'api.beebotte.com';
    if(this.protocol.toLowerCase() === 'http') this.port = 80; else this.port = 443; 
    if(options.port) this.port = options.port;

    this.sign = function(toSign) {
        var shaObj = new jsSHA(toSign, "TEXT");
        var hmac = shaObj.getHMAC(this.secretKey, "TEXT", "SHA-1", "B64");
        return (this.keyId + ':' + hmac);
    }

    this.signRequest = function(http_verb, content_md5, content_type, date, uri) {
      http_verb = http_verb.toUpperCase();

      //content MD5 is mandatory for Post/Put requests
      if((http_verb == 'POST' || http_verb == 'PUT') && (content_md5 == '') ) throw new Error('(BBT.Connector.signRequest) Content-MD5 header required for POST and PUT methods');

      var stringToSign = http_verb + '\n' + content_md5 + '\n' + content_type + '\n' + date + '\n' + uri;

      return this.sign(stringToSign);
    }
    
    this.getUriToSign = function (method, uri, data) {
      if( method === 'POST' || method === 'PUT' ) return uri;
      return (uri + (data? ('?' + jQuery.param( data )) : ''));
    };

    this.sendRequest = function(options, callback) {
      var self = this;
      options.method = options.method.toUpperCase();
      date = new Date().toUTCString();
      contentType = "application/json";
      md5 = '';
      if( options.method === 'POST' || options.method === 'PUT' ) md5 = b64_md5(options.data);
      beforeSend = function(xhr) {};
      if( options.is_public !== true ) {
        beforeSend = function(xhr) {
          if( md5 ) {xhr.setRequestHeader('Content-MD5', md5);}
          xhr.setRequestHeader("Authorization", self.signRequest(options.method, md5, contentType, '', self.getUriToSign(options.method, options.uri, options.data)));
          //xhr.setRequestHeader("Authorization", "lelelele");
          xhr.setRequestHeader('X-Bbt-Date', new Date().toUTCString());
        }
      }

      $.ajax({
        url: this.protocol + '://' + this.hostname + ':' + this.port.toString() + options.uri,
        type: options.method,
        dataType : 'json',
        data: options.data,
        contentType: contentType,
        beforeSend : beforeSend,
        success: function(body) {
          callback(null, body)
        },
        error: function(body) {
          callback(body, body)
        }
      });
    }
}

//{channel, resource, type}
BBT.Connector.prototype.readPublicResource = function(params, callback) {
  var self = this;
  var query_opts = { limit: (params.limit || 750) };
  if( params.source ) query_opts.source = params.source;
  if( params['time-range'] ) query_opts['time-range'] = params['time-range'];
  if( params['start-time'] ) query_opts['start-time'] = params['start-time'];
  if( params['end-time'] ) query_opts['end-time'] = params['end-time'];
  if( params['filter'] ) query_opts['filter'] = params['filter'];
  if( params['sample-rate'] ) query_opts['sample-rate'] = params['sample-rate'];

  options = {
    uri: '/v1/public/data/read/' + params.owner + '/' + params.channel + '/' + params.resource,
    data: query_opts,
    method: 'GET',
    is_public: true
  }
    
  return this.sendRequest(options, callback);
}

//{channel, resource, type}
BBT.Connector.prototype.readResource = function(params, callback) {
  var self = this;
  var query_opts = { limit: (params.limit || 750) };
  if( params.source ) query_opts.source = params.source;
  if( params['time-range'] ) query_opts['time-range'] = params['time-range'];
  if( params['start-time'] ) query_opts['start-time'] = params['start-time'];
  if( params['end-time'] ) query_opts['end-time'] = params['end-time'];
  if( params['filter'] ) query_opts['filter'] = params['filter'];
  if( params['sample-rate'] ) query_opts['sample-rate'] = params['sample-rate'];

  options = {
    uri: '/v1/data/read/' + params.channel + '/' + params.resource,
    data: query_opts,
    method: 'GET',
    is_public: false
  }
    
  return this.sendRequest(options, callback);
}

//{channel, resource, type, data}
BBT.Connector.prototype.writeResource = function(params, callback) {
  var self = this;
  var body = {data: params.data};
  if( params.ts ) body.ts = params.ts;
  var bodystr = JSON.stringify(body);
  options = {
    uri: '/v1/data/write/' + params.channel + '/' + params.resource,
    data: bodystr,
    method: 'POST',
    is_public: false
  }
    
  return this.sendRequest(options, callback);
}

//{channel, resource, type, data}
BBT.Connector.prototype.writeBulk = function(params, callback) {
  var self = this;
  var bodystr = JSON.stringify({records: params.records});
  options = {
    uri: '/v1/data/write/' + params.channel,
    data: bodystr,
    method: 'POST',
    is_public: false
  }
    
  return this.sendRequest(options, callback);
}

BBT.Connector.prototype.publish = function(params, callback) {
  var self = this;
  var body = {data: params.data};
  if( params.ts ) body.ts = params.ts;
  if( params.source ) body.source = params.source;
  var bodystr = JSON.stringify(body);
  options = {
    uri: '/v1/data/publish/' + params.channel + '/' + params.resource + '?' + (params['private']? 'private=true' : 'private=false'),
    data: bodystr,
    method: 'POST',
    is_public: false
  }
    
  return this.sendRequest(options, callback);
}

//{channel, resource, type, data}
BBT.Connector.prototype.publishBulk = function(params, callback) {
  var self = this;
  var bodystr = JSON.stringify({records: params.records});
  options = {
    uri: '/v1/data/publish/' + params.channel + '?' + (params['private']? 'private=true' : 'private=false'),
    data: bodystr,
    method: 'POST',
    is_public: false
  }
    
  return this.sendRequest(options, callback);
}

BBT.Connector.prototype.auth = function( sid, channel, resource, ttl, read, write ) {
  resource = resource || '*',
  ttl = ttl || 0,
  read = read || false,
  write = write || false,
  sid = sid;
  if( !sid || !channel ) return null;

  var to_sign = sid + ':' + channel + '.' + resource + ':ttl=' + ttl + ':read=' + read + ':write=' + write;
  return {auth: this.sign(to_sign)};
} 

