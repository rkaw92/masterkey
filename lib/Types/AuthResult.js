'use strict';

const ValueObject = require('./ValueObject');

/**
 * The AuthResult is a DTO that contains the result of an authentication request.
 * It holds the generated token and metadata about the course of authentication:
 * whether the token generated is final and what the next step is if not.
 * @extends ValueObject
 * @property {string} token - The generated token, in string format.
 * @property {boolean} final - Whether the token is final (i.e. allows logging on to the target system).
 * @property {?string[]} next - The next possible methods of authentication. Only one should be selected by the requester.
 */
class AuthResult extends ValueObject {
  constructor({ token, final = true, next = null }) {
    token = String(token);
    final = Boolean(final);
    if (!token || (!final && (!next || !Array.isArray(next) || next.length === 0))) {
      throw new Error('Invalid AuthResult data passed to the constructor');
    }
    super({ token, final, next });
  }
}

module.exports = AuthResult;
