const request = require('request');
const addy = 'mriiKYjbJzk4hgxTQ1uFTm4QZ3HTrkVn7U';
request("https://api.blockcypher.com/v1/btc/test3/addrs/"+addy+"/full", function (error, response, body) {
  console.log('error:', error); // Print the error if one occurred
  console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
  console.log('body[balance]:', JSON.parse(body)["balance"]); // Print the HTML for the Google homepage.
  console.log(parseFloat(JSON.parse(body)["balance"]*0.00000001))
  //event.sender.send('refresh', parseFloat(JSON.parse(body)["balance"]*0.00000001));
  //event.sender.send('btcaddress', addy);
});
