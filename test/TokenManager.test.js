'use strict';

const TokenManager = require('../lib/TokenManager');
const AuthChallenge = require('../lib/Types/AuthChallenge');
const JWT = require('jsonwebtoken');
const assert = require('assert');
const uuid = require('uuid');

// ### Definitions ###

const tokenKey = 'chess-verify=barrel';
// Simulation of a database-driven backend that looks up passwords:
const passwordBackend = {
  authenticate({ subjectID, secret }) {
    if (this.passwords[subjectID] && secret && this.passwords[subjectID] === secret) {
      return Promise.resolve();
    } else {
      return Promise.reject(new Error('Invalid password or no such user'));
    }
  },
  passwords: {
    user1: 'password1'
  }
};

// Simulation of a time-based authenticator (T/OTP semantics):
const dateBackend = {
  authenticate({ subjectID, secret }) {
    const inputDate = new Date(secret);
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0);
    const todayEnd = new Date();
    todayEnd.setHours(23, 59, 59, 999);
    if (inputDate.getTime() >= todayStart.getTime() && inputDate.getTime() <= todayEnd.getTime()) {
      return Promise.resolve();
    } else {
      return Promise.reject(new Error('Invalid time value'));
    }
  }
};

// Simulation of an authenticator that sends codes via an independent channel:
class CodeBackend {
  constructor({ codeCallback }) {
    this._userCodes = new Map();
    this._codeCallback = codeCallback;
  }

  requestChallenge({ subjectID }) {
    let code;
    if (this._userCodes.has(subjectID)) {
      code = this._userCodes.get(subjectID)
    } else {
      code = uuid.v4();
      this._userCodes.set(subjectID, code);
    }
    // "Send" the code by passing it to the callback provided upon construction:
    this._codeCallback({ subjectID, code });
    return Promise.resolve(new AuthChallenge({
      content: null,
      sent: true
    }));
  }

  authenticate({ subjectID, secret }) {
    const userCode = this._userCodes.get(subjectID);
    if (userCode && userCode === secret) {
      this._userCodes.delete(subjectID);
      return Promise.resolve();
    }
    return Promise.reject(new Error('Invalid code'));
  }
}

// ### Test body ###

describe('TokenManager', function() {
  describe('#getToken', function() {
    it('should generate a final token for a simple auth case', function() {
      const manager = new TokenManager({
        userDB: null,
        authBackends: { password: passwordBackend },
        authSteps: [ 'password' ],
        revokeDB: null,
        tokenParameters: { key: tokenKey }
      });
      return manager.getToken({
        subjectID: 'user1',
        secret: 'password1'
      }).then(function({ token, final }) {
        const payload = JWT.verify(token, tokenKey, {
          algorithms: [ 'HS256' ],
          subject: 'user1'
        });
        assert.equal(payload.from, 'password');
        assert.equal(payload.final, true);
        assert.equal(final, payload.final);
      });
    });
    it('should refuse invalid passwords', function() {
      const manager = new TokenManager({
        userDB: null,
        authBackends: { password: passwordBackend },
        authSteps: [ 'password' ],
        revokeDB: null,
        tokenParameters: { key: tokenKey }
      });
      return manager.getToken({
        subjectID: 'user1',
        secret: 'badPassword'
      }).then(function unexpectedSuccess() {
        throw new Error('Password is invalid, but authentication succeeded - this is a bug');
      }, function expectedRejection() {
        return;
      });
    });
    it('should handle a two-factor authentication scheme', function() {
      const manager = new TokenManager({
        userDB: null,
        authBackends: { password: passwordBackend, date: dateBackend },
        authSteps: [ 'password', 'date' ],
        revokeDB: null,
        tokenParameters: { key: tokenKey }
      });
      return manager.getToken({
        subjectID: 'user1',
        secret: 'password1'
      }).then(function(intermediateResult) {
        assert.equal(intermediateResult.final, false);
        assert.deepEqual(intermediateResult.next, [ 'date' ]);
        const intermediatePayload = JWT.verify(intermediateResult.token, tokenKey, { algorithms: [ 'HS256' ], subject: 'user1' });
        assert.equal(intermediatePayload.final, intermediateResult.final);
        assert.equal(intermediatePayload.from, 'password');
        // Authenticate against the 2nd step using the token from the 1st:
        return manager.getToken({
          subjectID: 'user1',
          secret: (new Date()).toISOString(),
          previousToken: intermediateResult.token
        });
      }).then(function(finalResult) {
        assert.equal(finalResult.final, true);
        assert(!finalResult.next);
        const finalPayload = JWT.verify(finalResult.token, tokenKey, { algorithms: [ 'HS256' ], subject: 'user1' });
        assert.equal(finalPayload.final, finalResult.final);
        assert.equal(finalPayload.from, 'date');
      });
    });
    it('should prevent skipping steps', function() {
      const manager = new TokenManager({
        userDB: null,
        authBackends: { password: passwordBackend, date: dateBackend },
        authSteps: [ 'password', 'date' ],
        revokeDB: null,
        tokenParameters: { key: tokenKey }
      });
      return manager.getToken({
        subjectID: 'user1',
        secret: (new Date()).toISOString(),
        method: 'date'
      }).then(function unexpectedSuccess() {
        throw new Error('Managed to skip a mandatory authentication step - this is a bug');
      }, function expectedRejection() {
        return;
      });
    });
  });
  describe('#requestChallenge', function() {
    it('should generate a challenge for a challenge-response authentication mechanism', function() {
      // Construct a new temporary "code database":
      let codeBackend;
      let manager;
      const authPromise = new Promise(function(fulfill, reject) {
        codeBackend = new CodeBackend({
          codeCallback: function({ subjectID, code }) {
            manager.getToken({ subjectID, secret: code }).then(fulfill);
          }
        });
      });

      manager = new TokenManager({
        userDB: null,
        authBackends: { code: codeBackend },
        authSteps: [ 'code' ],
        revokeDB: null,
        tokenParameters: { key: tokenKey }
      });

      manager.requestChallenge({ subjectID: 'user1' });

      return authPromise;
    });
  });
});
