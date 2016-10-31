var Packet = require('native-dns-packet');
var MongoClient = require('mongodb').MongoClient
var dateFormat = require('dateformat');

var pcap = require('pcap'),
    tcp_tracker = new pcap.TCPTracker(),
    pcap_session = pcap.createSession('eth0', "dst port 53");

var cassandra = require('cassandra-driver');
var client = new cassandra.Client({ contactPoints: ['h1:port1', 'h2:port2'], keyspace: 'keyspace_name'});
var countType = ["geo_filter", "geo_proximity", "standard"];

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    var domainName = Packet.parse(packet.payload.payload.payload.data).question[0].name.toLowerCase();
    
    MongoClient.connect( "connectionUrl", function( err, db ) {
    	db.collection('domain').find({name: domainName}, {_id: 1, accountId: 1}).toArray(function(err, docs) {
    		if(docs.length > 0){
		    var data = {};
		    data.domainId = docs[0]._id;
	            data.accountId = docs[0].accountId;
                    data.date = dateFormat(new Date(), "yyyy-mm-dd");
		    data.sourceId = 1;
		    data.countType = countType[Math.floor(Math.random() * countType.length)];
		    client.execute("Update real_time_stats_billing.agg_billing SET num_queries=num_queries+1 WHERE account_id=? and date=? and domain_id=? and source_id=? and count_type=?;", 
		    [data.accountId, data.date, data.domainId, data.sourceId, data.countType],{prepare: true}, 
                    function(err, result) 
		    {
   		    	if(err) console.log(err);	
		    });
                }
		db.close();
    	});
    });

});
