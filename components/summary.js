'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details.body'),

  summaryTags: Ember.computed('details.risk', function(){
        let summaryTags = [];

        if(this.get('details.risk')){
            summaryTags.push("Risk: " + this.get('details.risk'));
        }
        return summaryTags;
    }),

    typeTags: Ember.computed('details.risk_recommended', function(){
          let typeTags = [];

          if(this.get('details.risk_recommended')){
              typeTags.push("Risk Recommendation: " + this.get('details.risk_recommended'));
          }
          return typeTags;
      })
});
