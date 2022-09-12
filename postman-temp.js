//use a dummy Interval object, so we can use async/await to have a clean method of chaining an asynchronous call with the logic that requires the response.
const _dummy = setInterval(() => {}, 300000);

function sendRequest(req) {
    return new Promise((resolve, reject) => {
        pm.sendRequest(req, (err, res) => {
            if (err) {
                return reject(err);
            }
            return resolve(res);
        })
    });
}

(async function main() {
    //If the RSA signing library is not loaded in the jsrsasign-js environment variable, make the http call to get the library
    if (pm.environment.has("jsrsasign-js")) {
        const result = await sendRequest('http://kjur.github.io/jsrsasign/jsrsasign-latest-all-min.js');
        pm.environment.set("jsrsasign-js", result.text())
    }
    clearInterval(_dummy)


    var navigator = {}; //fake a navigator object for the lib
    var window = {}; //fake a window object for the lib
    eval(pm.environment.get("jsrsasign-js"));

    var privateKey = pm.environment.get('ob-seal-private-key');

    var currentTimestamp = Math.floor(Date.now() / 1000 )
    var header = {
        'typ': 'JOSE',
        'alg': 'PS256',
        "kid":"zPeFbX7nJokEVpynzayWvgtFBxo",
        'http://openbanking.org.uk/iat': currentTimestamp,
        'http://openbanking.org.uk/iss': 'CN=0015800001041REAAY,organizationIdentifier=PSDGB-OB-Unknown0015800001041REAAY,O=FORGEROCK LIMITED,C=GB',
        'http://openbanking.org.uk/tan': 'openbanking.org.uk',
        'crit': [
            'http://openbanking.org.uk/iat',
            'http://openbanking.org.uk/iss',
            'http://openbanking.org.uk/tan'
        ]
    };

//var data = pm.environment.get('patchedDomesticPaymentConsent')
    var data=pm.request.body.toString()
    console.log("data: " + data)

//console.log(`header: ${ JSON.stringify(header)}`);

    var jwt =  KJUR.jws.JWS.sign(null, header, data, privateKey);
    console.log("JWT:" + jwt);

    var jwtElements = jwt.split(".");
    var jws_signature = jwtElements[0] + ".." + jwtElements[2];

    console.log("jws_signature:" + jws_signature);

// For investigations regading possible differences in payload, set the "jwt" parameter on the x-jws-signature variable in this point
//postman.setEnvironmentVariable("x-jws-signature", jws_signature);
    pm.environment.set('jws-signature', jws_signature);
    console.log("Exit script");
})();
