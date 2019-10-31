const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
  // Get the token from the header
  const token = req.header('x-auth-token');

  // Check if no token
  if (!token) {
    return res.status(401).json({ msg: 'No token. Authorization denied' });
  }

  // Verify token
  try {
    // Parse the JWT string and store the result in `payload`.
    // Note that we are passing the key in this method as well. This method will throw an error
    // if the token is invalid (if it has expired according to the expiry time we set on sign in),
    // or if the signature does not match
    const payload = jwt.verify(token, config.get('jwtSecret'));

    req.user = payload.user;

    next();
  } catch (err) {
    // Invalid token
    res.status(401).json({ msg: 'Invalid token. Authorization denied' });
  }
};
