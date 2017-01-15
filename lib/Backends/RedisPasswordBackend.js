'use strict';

const Redis = require('ioredis');
const bcrypt = require('bcrypt');
const { AuthenticationFailed } = require('../Errors');

/**
 * The RedisPasswordBackend is a simple password-based authentication back-end.
 * It supports challenge-less authentication based on passwords stored in
 *  a hashed, salted form in a Redis DB.
 */
class RedisPasswordBackend {
  /**
   * Create a new RedisPasswordBackend.
   * @param {Object} [options]
   * @param {Object} [options.config] - The connection/DB configuration.
   * @param {number} [options.config.port=6379] - The redis server's TCP port.
   * @param {string} [options.config.host=127.0.0.1] - The host to connect to.
   * @param {number} [options.config.family=4] - The address family (IP version) to use for connecting (4 or 6).
   * @param {string} [options.config.prefix='masterkey'] - The string to prefix all used Redis keys with.
   */
  constructor({ config: { port = 6379, host = '127.0.0.1', family = 4, prefix = 'masterkey' } = {} } = {}) {
    this._db = new Redis({ port, host, family });
    this._prefix = prefix;
  }

  /**
   * Initialize the backend.
   * @returns {Promise}
   */
  init() {
    return Promise.resolve();
  }

  authenticate({ subjectID, secret }) {
    // Get the key associated with the user:
    return this._db.get(`${this._prefix}:${subjectID}`).then(function _checkPassword(data) {
      if (!data) {
        return Promise.reject(new AuthenticationFailed());
      }
      return bcrypt.compare(secret, data).then(function(passwordMatches) {
        if (!passwordMatches) {
          throw new AuthenticationFailed();
        }
      });
    });
  }
}

module.exports = RedisPasswordBackend;
