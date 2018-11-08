'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;
let domainBlackList = [];
let previousDomainBlackListAsString = '';
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlacklistRegex = null;
let ipBlacklistRegex = null;

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

function startup(logger) {
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

  requestWithDefaults = request.defaults(defaults);
}

function _setupRegexBlacklists(options) {
  if (
    options.domainBlacklistRegex !== previousDomainRegexAsString &&
    options.domainBlacklistRegex.length === 0
  ) {
    Logger.debug('Removing Domain Blacklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlacklistRegex = null;
  } else {
    if (options.domainBlacklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlacklistRegex;
      Logger.debug(
        { domainBlacklistRegex: previousDomainRegexAsString },
        'Modifying Domain Blacklist Regex'
      );
      domainBlacklistRegex = new RegExp(options.domainBlacklistRegex, 'i');
    }
  }

  if (options.blacklist !== previousDomainBlackListAsString && options.blacklist.length === 0) {
    Logger.debug('Removing Domain Blacklist Filtering');
    previousDomainBlackListAsString = '';
    domainBlackList = null;
  } else {
    if (options.blacklist !== previousDomainBlackListAsString) {
      previousDomainBlackListAsString = options.blacklist;
      Logger.debug(
        { domainBlacklist: previousDomainBlackListAsString },
        'Modifying Domain Blacklist Regex'
      );
      domainBlackList = options.blacklist.split(',').map((item) => item.trim());
    }
  }

  if (
    options.ipBlacklistRegex !== previousIpRegexAsString &&
    options.ipBlacklistRegex.length === 0
  ) {
    Logger.debug('Removing IP Blacklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlacklistRegex = null;
  } else {
    if (options.ipBlacklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlacklistRegex;
      Logger.debug({ ipBlacklistRegex: previousIpRegexAsString }, 'Modifying IP Blacklist Regex');
      ipBlacklistRegex = new RegExp(options.ipBlacklistRegex, 'i');
    }
  }
}

function doLookup(entities, options, cb) {
  const lookupResults = [];
  const tasks = [];

  _setupRegexBlacklists(options);

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (_isValidEntity(entity) === false || _isEntityBlacklisted(entity)) {
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

    tasks.push(function(done) {
      requestWithDefaults(requestOptions, function(error, res, body) {
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

function _isEntityBlacklisted(entityObj, options) {
  if (domainBlackList.indexOf(entityObj.value) >= 0) {
    return true;
  }

  if (entityObj.isIPv4 && !entityObj.isPrivateIP) {
    if (ipBlacklistRegex !== null) {
      if (ipBlacklistRegex.test(entityObj.value)) {
        Logger.debug({ ip: entityObj.value }, 'Blocked BlackListed IP Lookup');
        return true;
      }
    }
  }

  if (entityObj.isDomain) {
    if (domainBlacklistRegex !== null) {
      if (domainBlacklistRegex.test(entityObj.value)) {
        Logger.debug({ domain: entityObj.value }, 'Blocked BlackListed Domain Lookup');
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
function _isValidEntity(entity) {
  if (entity.isIP && (entity.isPrivateIP || IGNORED_IPS.has(entity.value))) {
    return false;
  }
  return true;
}

function _filterOutRiskLevel(body, options) {
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

function _isMiss(body) {
  if (typeof body.error === 'string' && body.error === 'Indicator not found.') {
    return true;
  }
  return false;
}

function validateOptions(userOptions, cb) {
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
