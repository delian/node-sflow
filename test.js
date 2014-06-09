/**
 * Created by delian on 6/6/14.
 */
var Collector = require('./sflow.js');

Collector(function(msg) {
    console.log(msg);
}).listen(6344);
