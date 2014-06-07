node-sflow
==========

Sflow compatible library

The library is still under development, please be careful! It has been tested with Extreme XOS only! Please raise issues in case of problem!

## Usage

The usage of the Sflow collector library is very very simple. You just have to do something like this:


    var Collector = require('node-sflow');
    
    Collector(function(flow) {
        console.log(flow);
    }).listen(3000);
