const jwt = require('jsonwebtoken');

require('dotenv').config();
const expiration = '2h';

module.exports = {
    signToken: function({ username, email, _id }) {
        const payload = { username, email, _id };
        return jwt.sign({ data: payload }, process.env.SECRET, { expiresIn: expiration });
    },
    authMiddleware: function({ req }) {
        // allows token to be sent vie req.body, req.query, or headers
        let token = req.body.token || req.query.token || req.headers.authorization;

        // serparate "Bearer" from "<tokenvalue>"
        if(req.headers.authorization) {
            token = token
                .split(' ')
                .pop()
                .trim();
        }

        // if no token, return request object as is
        if (!token) {
            return req;
        }

        try {
            // decode and attach user data to request object
            const { data } = jwt.verify(token, process.env.SECRET, {maxAge: expiration});
            req.user = data;
        } catch {
            console.log('Invalid token');
        }

        // return updated request object
        return req;
    }
}