const checkout = require('./checkout');
const webhook = require('./webhook');
const customer = require('./customer');

module.exports = {
  ...checkout,
  ...webhook,
  ...customer
};
