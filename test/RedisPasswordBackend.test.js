'use strict';

const TokenManager = require('../lib/TokenManager');
const RedisPasswordBackend = require('../lib/Backends/RedisPasswordBackend');
const Redis = require('ioredis');
const bcrypt = require('bcrypt');
const JWT = require('jsonwebtoken');
const assert = require('assert');

const port = process.env.REDIS_PORT || 6379;
const key = 'mode_column8really';
const prefix = 'masterkeytest';

describe('RedisPasswordBackend', function() {
  let manager;
  before(function() {
    const redisBackend = new RedisPasswordBackend({
      config: { port, prefix }
    });
    manager = new TokenManager({
      authBackends: { password: redisBackend },
      authSteps: [ 'password' ],
      tokenParameters: { key }
    });
    return redisBackend.init().then(function _prepareUserAccounts() {
      const db = new Redis({ port });
      return db.set(`${prefix}:user1`, bcrypt.hashSync('sugar-Guilt-Rex', 12));
    });
  });

  it('should authenticate an existing user', function() {
    return manager.getToken({
      subjectID: 'user1',
      secret: 'sugar-Guilt-Rex'
    }).then(function({ token, final }) {
      const payload = JWT.verify(token, key, {
        algorithms: [ 'HS256' ],
        subject: 'user1'
      });
      assert.equal(payload.from, 'password');
      assert.equal(payload.final, true);
      assert.equal(final, payload.final);
    });
  });
});
