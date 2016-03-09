const nconf = require('nconf');
const Auth0 = require('auth0');
const request = require('request');
const winston = require('winston');
const fs = require('fs');
const sleep = require('sleep');
const CSV = require('comma-separated-values');

const logger = new winston.Logger({
    transports: [
        new winston.transports.Console({
            timestamp: true,
            level: 'debug',
            handleExceptions: true,
            json: false,
            colorize: true
        })
    ],
    exitOnError: false
});

nconf.argv()
  .env()
  .file({ file: './config.json' });

const auth0 = new Auth0({
  domain: nconf.get('AUTH0_DOMAIN'),
  clientID: nconf.get('AUTH0_CLIENT_ID'),
  clientSecret: nconf.get('AUTH0_CLIENT_SECRET')
});

const logs = [];
const createRow = function(record, log_type) {
    var isLogin = false;

    if(record.client_id){
	if(record.client_id != nconf.get('AUTH0_CLIENT_ID')){
	    //if not our client id (i.e. not what we are looking for), then return null
	    //effectivly skipping this log.
	    return null;
	}
    }
    if (log_type[record.type]) {
        record.type = log_type[record.type].event
	if(record.type != 'Success Login') {
	    //not a success login, so skip this result.
	    return null;
	}
    }
    if (record.description) {
	record.description = record.description.replace(/(\s+|\;)/g, ' ');
    }

    if (record.details) {
	record.details = JSON.stringify(record.details).replace(/(\s+|\;)/g, ' ');
    }

    return record;
};

const toCSV = function(data){
    var columns = [];
    var output = "";

    //loop over all logs
    for(var i = 0; i < data.length; i++){
	var current = data[i];
	//if it is a valid object, continue.
	if(current && typeof current != 'undefined'){
	    //needs header? if so, get header and output header
	    if(columns.length == 0){
		//needs header so get all values for the objects based on the
		//first object in the list.
		columns = Object.keys(current);
		//loop over all keys (a.k.a. column headers and output them.
		for(var j = 0; j < columns.length; j++){
		    //print header
		    output += columns[j];
		    //if not the last one, print out a comma to denote a new column.
		    if(columns.length != i + 1)	output += ',';
		}
		//end of column header so add newline
		output += '\n';
	    }
	    //loop over all properties of an item and output the corresponding value.
	    for(var j = 0; j < columns.length; j++){
		//if there is a value for the current column
		if(current[columns[j]]){
		    //output the value of the column
		    output += current[columns[j]];
		}
		//append a comma if it isn't the last property/column.
		if(columns.length != i + 1)	output += ',';
	    }
	    //end of row, so append newline.
	    output += '\n';
	}
    }
    //return CSV formatted content. Rows are seperated by using \n.
    return output;
}

const done = function() {
    logger.info('All logs have been downloaded, total: ' + logs.length);

    var log_type = getLogTypes();

    //loop over all the types and don't use null values.
    var data = [];
    for(var i = 0; i < logs.length; i++){
	var log =  createRow(logs[i], log_type);
	if(log && typeof(log) != "undefined" && log != undefined) {	    
	    data[i] = log;
	}
    }
    
    var output = toCSV(data);
    fs.writeFileSync('./auth0-logs.csv', output);
};

const getLogs = function(checkPoint) {
    //this needs to be here so we don't hit the API too many requests error.
    sleep.sleep(3);
    //get the next 200 logs
    auth0.getLogs({ take: 200, from: checkPoint }, function(err, result) {
	if (err) {
            return logger.error('Error getting logs', err);
	}

	if (result && result.length > 0) {
	    //add all the logs in this batch to our working set.
            result.forEach(function(log) {
		logs.push(log);
            });

            logger.info('Processed ' + logs.length + ' logs.');
            setImmediate(function() {
		//loop and process the next batch.
		getLogs(logs[logs.length - 1]._id);
            });
	}
	else {
	    //no more ressults, so we are done. now convert to csv.
	    done();
	}
    });
};

logger.info('Starting export...');

auth0.getAccessToken(function (err, newToken) {
  logger.debug('Authenticating...');

  if (err) {
    logger.error('Error authenticating', err);
    return;
  }

  logger.debug('Authentication success.');
  getLogs();
});

const getLogTypes = function() {
  return {
    's': {
      event: 'Success Login'
    },
    'seacft': {
      event: 'Success Exchange'
    },
    'feacft': {
      event: 'Failed Exchange'
    },
    'f': {
      event: 'Failed Login'
    },
    'w': {
      event: 'Warnings During Login'
    },
    'du': {
      event: 'Deleted User'
    },
    'fu': {
      event: 'Failed Login (invalid email/username)'
    },
    'fp': {
      event: 'Failed Login (wrong password)'
    },
    'fc': {
      event: 'Failed by Connector'
    },
    'fco': {
      event: 'Failed by CORS'
    },
    'con': {
      event: 'Connector Online',
    },
    'coff': {
      event: 'Connector Offline'
    },
    'fcpro': {
      event: 'Failed Connector Provisioning'
    },
    'ss': {
      event: 'Success Signup'
    },
    'fs': {
      event: 'Failed Signup'
    },

    'cs': {
      event: 'Code Sent'
    },
    'cls': {
      event: 'Code/Link Sent'
    },
    'sv': {
      event: 'Success Verification Email'
    },
    'fv': {
      event: 'Failed Verification Email'
    },
    'scp': {
      event: 'Success Change Password'
    },
    'fcp': {
      event: 'Failed Change Password'
    },
    'sce': {
      event: 'Success Change Email'
    },
    'fce': {
      event: 'Failed Change Email'
    },
    'scu': {
      event: 'Success Change Username'
    },
    'fcu': {
      event: 'Failed Change Username'
    },
    'scpn': {
      event: 'Success Change Phone Number'
    },
    'fcpn': {
      event: 'Failed Change Phone Number'
    },
    'svr': {
      event: 'Success Verification Email Request'
    },
    'fvr': {
      event: 'Failed Verification Email Request'
    },
    'scpr': {
      event: 'Success Change Password Request'
    },
    'fcpr': {
      event: 'Failed Change Password Request'
    },
    'fn': {
      event: 'Failed Sending Notification'
    },
    'sapi': {
      event: 'API Operation'
    },
    'fapi': {
      event: 'Failed API Operation'
    },
    'limit_wc': {
      event: 'Blocked Account'
    },
    'limit_ui': {
      event: 'Too Many Calls to /userinfo'
    },
    'api_limit': {
      event: 'Rate Limit On API'
    },
    'sdu': {
      event: 'Successful User Deletion'
    },
    'fdu' : {
      event: 'Failed User Deletion'
    }
  };
};
