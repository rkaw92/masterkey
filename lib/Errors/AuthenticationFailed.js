'use strict';

class AuthenticationFailed extends Error {
  constructor(data) {
    super('Authentication failed');
    this.data = data;
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, AuthenticationFailed);
    }
  }
}

module.exports = AuthenticationFailed;
