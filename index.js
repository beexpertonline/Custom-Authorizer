const jwt = require('jsonwebtoken');
const config = require('./config');

function extractTokenFromHeader(e) {
    if (e.authorizationToken && e.authorizationToken.split(' ')[0] === 'Bearer') {
        return e.authorizationToken.split(' ')[1];
    } else {
        return e.authorizationToken;
    }
}

function validateToken(token, secret) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, secret, null, function (error) {
            if (error) {
                console.log(`error is `, error.message)
                resolve("Unauthorized")
            } else {
                resolve("allow")
            }
        })
    });
}

function generatePolicyDocument(effect, methodArn) {
    if (!effect || !methodArn) return null

    const policyDocument = {
        Version: '2012-10-17',
        Statement: [{
            Action: 'execute-api:Invoke',
            Effect: effect,
            Resource: methodArn
        }]
    };

    return policyDocument;
}

function generateAuthResponse(principalId, effect, methodArn) {
    const policyDocument = generatePolicyDocument(effect, methodArn);

    return {
        principalId,
        policyDocument
    }
}


exports.handler = async (event, context, callback) => {
    const methodArn = event.methodArn;
    try {
        let token = extractTokenFromHeader(event) || '';
        let tokenRes = await validateToken(token, config.secret);
        if (tokenRes == 'allow') {
            return callback(null, generateAuthResponse('user', 'Allow', methodArn));
        } else {
            return callback(null, generateAuthResponse('user', 'Deny', methodArn));
        }
    } catch (error) {
        return callback(null, generateAuthResponse('user', 'Deny', methodArn));
    }

}


