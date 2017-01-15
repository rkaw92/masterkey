'use strict';

const ValueObject = require('./ValueObject');

/**
 * An AuthChallenge is a DTO that describes a challenge put before the user
 *  for them to solve. A challenge may be interactive (rely on displaying
 *  a puzzle or an input for the user to enter their pre-defined data into),
 *  or it may use an independent messaging channel for delivering the necessary
 *  information (e.g. a one-time password sent via SMS or e-mail), requiring the
 *  user to demonstrate ownership of the associated inbox.
 * @extends ValueObject
 * @property {?Object} content - The content of the challenge. Its shape depends on the method being used. Can be null if the question posed by a challenge is constant/obvious - for instance, re-typing a code sent via an SMS will have no variable elements in the question part.
 * @property {string} method - Name of the authentication method for which the challenge has been generated.
 * @property {boolean} sent - Whether this challenge has resulted in sending any information to the user being challenged. If true, it is an indicator that the user should check their inbox.
 */
class AuthChallenge extends ValueObject {
  constructor({ content = null, method, sent = false }) {
    method = String(method);
    sent = Boolean(sent);
    super({ content, method, sent });
  }
}

module.exports = AuthChallenge;
