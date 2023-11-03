const { verifyJWT } = require('../../utils/jwt');
const HTTP_STATUS = require('../../config/constants');

const sendUnauthorizedResponse = (res, message) => {
  return res.status(HTTP_STATUS.unauthorized.code).json({
    code: HTTP_STATUS.unauthorized.code,
    message: message
  });
};

const verifyToken = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;

  if (!authorizationHeader) {
    return sendUnauthorizedResponse(res, HTTP_STATUS.unauthorized.text.op1);
  }

  const [bearer, token] = authorizationHeader.split(' ');

  if (bearer !== 'Bearer' || !token) {
    return sendUnauthorizedResponse(res, HTTP_STATUS.unauthorized.text.op2);
  }

  try {
    if (verifyJWT(token)) {
      return next();
    } else {
      return sendUnauthorizedResponse(res, HTTP_STATUS.unauthorized.text.op3);
    }
  } catch (error) {
    return sendUnauthorizedResponse(res, HTTP_STATUS.unauthorized.text.op3);
  }
};

module.exports = { verifyToken };