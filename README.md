# Polarity Pulsedive Integration

The Polarity Pulsedive integration allows Polarity to search Pulsedive to return threat information on domains and IPs.

![image](https://user-images.githubusercontent.com/306319/47765161-036a2980-dc9f-11e8-91fc-cf8f2583291f.png)

## Pulsedive Integration Options

### API Key

A free API Key is provided by Pulsedive, however there is a rate limit of 30 requests per minute.

https://pulsedive.com/account/

### Risk Levels to Display

Only display indicators that have a Risk value greater or equal to the selected risk level.

### Show Indicators with Unknown Risk

If checked, the integration will display indicators with an Risk level of "unknown".

### Ignored Entities

Comma delimited list of domains that you do not want to lookup.

### Ignored Domain Regex

Domains that match the given regex will not be looked up.

#### Regex to Ignore Domain and Subdomains

The below Ignored Domain Regex will ignore the domain `google.com` and all of its subdomains.

```
^(.*\.google\.com|google\.com)
```

#### Regex to Ignore Subdomains

The following regex will ignore all subdomains of `google`:

```
^.*\.google\.com
```

If you also wanted to ignore the base domain you could add the following to your `Ignored Domain Regex` option:

```
google.com
```

#### Ignoring Multiple Domains

You can also ignore multiple domains.  For example, if you wanted to ignore all subdomains of `linkedin` and `google` you could add this to the Ignored Domain Regex:

```
^(.*\.google\.com|.*\.linkedin\.com)
```

The above regex will ignore all subdomains of `google` and `linkedin`.  Then in your comma delimited list you would do:

```
google.com, linkedin.com
```

This will ignore the actual domain `google.com` and `linkedin.com`.

### Ignored IP Regex

IPs that match the given regex will not be looked up.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
