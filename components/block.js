polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  maxThreats: 10,
  maxRiskFactors: 10,
  maxRedirects: 10,
});
