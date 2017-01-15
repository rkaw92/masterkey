'use strict';

const JWT = require('jsonwebtoken');
const when = require('when');
const nodefn = require('when/node');
const AuthResult = require('./Types/AuthResult');
const AuthChallenge = require('./Types/AuthChallenge');

class TokenManager {
  constructor({ userDB, authBackends, authSteps, revokeDB, tokenParameters }) {
    this._userDB = userDB;
    this._authBackends = authBackends;
    this._authSteps = authSteps;
    this._revokeDB = revokeDB;
    this._tokenParameters = tokenParameters;
  }

  _getTokenForSecret({ subjectID, secret, method, final }) {
    const self = this;
    const backend = self._authBackends[method];
    return backend.authenticate({ subjectID, secret }).then(function() {
      return nodefn.call(JWT.sign, {
        from: method,
        final: final
      }, self._tokenParameters.key, {
        algorithm: 'HS256',
        expiresIn: '8h',
        subject: subjectID
      });
    });
  }

  /**
   * Check whether a token is valid for a given subject and that it is
   *  an intermediate token which can be used to access the selected
   *  authentication method.
   * @param {Object} params
   * @param {?string} params.previousToken - The token obtained from the previous authentication step, if any. If not passed and the chosen method is an initial method, the verification always succeeds.
   * @param {string} params.subjectID - ID of the subject for which to verify the token. If the subject in the previous token does not match this value, the verification fails.
   * @param {?string} params.method - The next method for which to verify the previous token. This adds a verification condition that requires the next method to be accessible from the previous one.
   * @returns {Promise.<Object>}
   */
  _verifyPreviousToken({ previousToken = null, subjectID, method = null }) {
    const self = this;
    const authSteps = self._authSteps;
    let verificationPromise;
    if (previousToken) {
      verificationPromise = nodefn.call(JWT.verify, previousToken, self._tokenParameters.key, {
        algorithms: [ 'HS256' ],
        subject: subjectID
      });
    } else {
      verificationPromise = when.resolve(null);
    }

    let previousMethodIndex;
    let currentMethodIndex;
    return verificationPromise.then(function(payload) {
      if (payload) {
        // Result being present is equivalent to previousToken being not null.
        const { from, final } = payload;
        // Sanity check: final tokens are not intermediate, so no other methods should follow them.
        if (final) {
          throw new Error('The token passed as previous token was a final token - no subsequent authentication is needed');
        }
        // Verify that the requested authentication method immediately follows the previous method ("from") in the method list.
        previousMethodIndex = authSteps.indexOf(from);
        // Sanity check: make sure the requester came from a step that actually exists.
        if (previousMethodIndex < 0) {
          throw new Error('The previous authentication step is invalid');
        }
        // If the method has not been specified, select the next method after the last authenticated method:
        if (!method) {
          method = authSteps[previousMethodIndex + 1];
        }
        currentMethodIndex = authSteps.indexOf(method);
        if (currentMethodIndex < 0 || (currentMethodIndex !== previousMethodIndex + 1)) {
          throw new Error('Invalid authentication method selected');
        }
      } else {
        // Default the method to the first applicable method if not explicitly passed:
        if (!method) {
          method = authSteps[0];
        }
        currentMethodIndex = authSteps.indexOf(method);
        if (currentMethodIndex !== 0) {
          throw new Error('Invalid authentication method selected');
        }
      }
      return {
        payload,
        method
      };
    });
  }

  /**
   * Request a final or intermediate authentication token.
   * If the system or user configuration requires that multi-factor
   *  authentication be used, providing the first factor (usually the password)
   * will yield an intermediate token which must be passed to subsequent
   * steps.
   * @param {Object} params
   * @param {?string} params.previousToken - The intermediate token, if any, obtained from the previous authentication step.
   * @param {string} params.subjectID - The ID for which a token is desired.
   * @param {string} params.secret - The secret piece of information (e.g. a password).
   * @param {?string} params.method - The chosen method of authentication for this authentication step. Only applicable if there are many to choose from.
   * @returns {Promise.<AuthResult>} - A Promise for the result object, which contains the token and progress information.
   */
  getToken({ previousToken = null, subjectID, secret, method = null }) {
    const self = this;
    const authSteps = self._authSteps;
    const verificationPromise = self._verifyPreviousToken({ previousToken, subjectID, method });
    return verificationPromise.then(function(verificationResult) {
      const currentMethodIndex = authSteps.indexOf(verificationResult.method);
      const currentMethodIsFinal = (currentMethodIndex === authSteps.length - 1);
      return self._getTokenForSecret({
        subjectID,
        secret,
        method: verificationResult.method,
        final: currentMethodIsFinal
      }).then(function(token) {
        return new AuthResult({
          token,
          final: currentMethodIsFinal,
          next: currentMethodIsFinal ? null : [ authSteps[currentMethodIndex + 1] ]
        });
      });
    });
  }

  /**
   * Request that a challenge be presented, either by yielding it in the
   *  returned promise, or by sending it via an independent channel to the
   *  authenticating user. For instance, for an authentication method that
   *  requires the user to click a link in an e-mail message, this method shall
   *  cause the e-mail to be sent.
   * @param {Object} params
   * @param {string} params.subjectID - The ID of the subject for which the challenge is needed.
   * @param {?string} params.previousToken - The token obtained from the previous authentication step, if any.
   * @param {?string} params.method - The method selected for this authentication step. Can be skipped if only one method is available.
   * @returns {Promise.<AuthChallenge>} A Promise that fulfills with information about the presented challenge.
   */
  requestChallenge({ subjectID, previousToken = null, method = null }) {
    const backends = this._authBackends;
    return this._verifyPreviousToken({ subjectID, previousToken, method }).then(function({ payload, method: chosenMethod }) {
      return backends[chosenMethod].requestChallenge({ subjectID });
    });
  }
}

module.exports = TokenManager;
