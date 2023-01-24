'use strict';

const request = require('postman-request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;
let domainBlockList = [];
let previousDomainBlockListAsString = '';
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

const MAX_PARALLEL_LOOKUPS = 10;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);
const RISK_LEVELS = {
  unknown: -1,
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

function startup (logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupRegexBlocklists (options) {
  if (
    options.domainBlocklistRegex !== previousDomainRegexAsString &&
    options.domainBlocklistRegex.length === 0
  ) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug(
        { domainBlocklistRegex: previousDomainRegexAsString },
        'Modifying Domain Blocklist Regex'
      );
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.blocklist !== previousDomainBlockListAsString && options.blocklist.length === 0) {
    Logger.debug('Removing Domain Blocklist Filtering');
    previousDomainBlockListAsString = '';
    domainBlockList = null;
  } else {
    if (options.blocklist !== previousDomainBlockListAsString) {
      previousDomainBlockListAsString = options.blocklist;
      Logger.debug(
        { domainBlocklist: previousDomainBlockListAsString },
        'Modifying Domain Blocklist Regex'
      );
      domainBlockList = options.blocklist.split(',').map((item) => item.trim());
    }
  }

  if (
    options.ipBlocklistRegex !== previousIpRegexAsString &&
    options.ipBlocklistRegex.length === 0
  ) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function doLookup (entities, options, cb) {
  const lookupResults = [];
  const tasks = [];

  _setupRegexBlocklists(options);

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (_isValidEntity(entity) === false || _isEntityBlocklisted(entity)) {
      Logger.debug({ entity: entity.value }, 'Ignoring Entity');
      return;
    }

    //do the lookup
    const requestOptions = {
      uri: 'https://pulsedive.com/api/info.php',
      qs: {
        indicator: entity.value,
        pretty: 1,
        key: options.apiKey
      },
      method: 'GET',
      json: true
    };

    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        Logger.trace(
          { body: body, statusCode: res ? res.statusCode : 'Not Available', entity: entity.value },
          'Result of Lookup'
        );

        if (error) {
          return done({
            detail: 'Error in HTTP Request',
            error: error
          });
        }

        if (_isMiss(body)) {
          return done(null, {
            entity: entity,
            body: null
          });
        }

        if (res.statusCode !== 200) {
          return done({
            detail: 'Unexpected HTTP Status Code Received',
            statusCode: res.statusCode,
            body: body
          });
        }

        // Pulsdive returns errors in an error property so we check for this property to see if we need to
        // handle an error.  Note that pulsedive also returns an error for 404's so we have to check _isMiss first
        if (typeof body.error !== 'undefined') {
          return done({
            detail: 'There was an error querying Pulsedive',
            error: body.error
          });
        }

        if (_filterOutRiskLevel(body, options)) {
          return done(null, null);
        }

        done(null, {
          entity: entity,
          body: body
        });
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      return cb(err);
    }

    results.forEach((result) => {
      if (result === null) {
        // skip this entity because it was filtered out
        return;
      }

      if (result.body === null) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: [],
            details: result.body
          }
        });
      }
    });

    cb(null, lookupResults);
  });
}

function _isEntityBlocklisted (entityObj, options) {
  if (domainBlockList.indexOf(entityObj.value) >= 0) {
    return true;
  }

  if (entityObj.isIPv4 && !entityObj.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entityObj.value)) {
        Logger.debug({ ip: entityObj.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  if (entityObj.isDomain) {
    if (domainBlocklistRegex !== null) {
      if (domainBlocklistRegex.test(entityObj.value)) {
        Logger.debug({ domain: entityObj.value }, 'Blocked BlockListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

/**
 * Skip RFC-1918 IP Addresses
 * @param entity
 * @returns {boolean}
 * @private
 */
function _isValidEntity (entity) {
  if (entity.isIP && (entity.isPrivateIP || IGNORED_IPS.has(entity.value))) {
    return false;
  }
  return true;
}

function _filterOutRiskLevel (body, options) {
  if (body.risk === 'unknown' && options.showUnknownRisk === true) {
    return false;
  }

  const resultLevel = RISK_LEVELS[body.risk];
  const targetLevel = RISK_LEVELS[options.riskLevelDisplay.value];

  if (resultLevel >= targetLevel) {
    return false;
  }

  return true;
}

function _isMiss (body) {
  if (typeof body.error === 'string' && body.error === 'Indicator not found.') {
    return true;
  }
  return false;
}

function validateOptions (userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a PulseDive API key'
    });
  }
  cb(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
