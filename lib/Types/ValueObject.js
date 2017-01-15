'use strict';

class ValueObject {
  constructor(data) {
    Object.keys(data).forEach(function(key) {
      this[key] = data[key];
    }, this);
    Object.freeze(this);
  }
}

module.exports = ValueObject;
