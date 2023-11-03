const daoSQL = require('../models/Users.dao');
const { jwtSign, verifyJWT } = require('../../utils/jwt');
const { HTTP_STATUS } = require('../../config/constants');

const getDecodedEmail = (req) => {
  const token = req.headers.authorization.split(' ')[1];
  return verifyJWT(token).email;
};

const sendResponse = (res, status, body) => res.status(status).json(body);

const findSingleUserRequest = async (req, res) => {
  try {
    const email = getDecodedEmail(req);
    const user = await daoSQL.findSingleUserFromDB(email);
    if (user.length) {
      sendResponse(res, HTTP_STATUS.ok.code, [{ email: user[0].email, rol: user[0].rol, lenguage: user[0].lenguage }]);
    } else {
      sendResponse(res, HTTP_STATUS.not_found.code, { code: HTTP_STATUS.not_found.code, message: HTTP_STATUS.not_found.text });
    }
  } catch (error) {
    sendResponse(res, HTTP_STATUS.internal_server_error.code, error);
  }
};

const authenticationRequest = async (req, res) => {
  const { email, password } = req.body;
  const isCorrect = await daoSQL.isPasswordCorrect(email, password);

  if (!isCorrect) {
    return sendResponse(res, HTTP_STATUS.not_found.code, { code: HTTP_STATUS.incorrect_pasword.code, message: HTTP_STATUS.incorrect_pasword.text });
  }
  
  try {
    const user = await daoSQL.findSingleUserFromDB(email);
    if (user.length) {
      const token = jwtSign({ email: user[0].email });
      sendResponse(res, HTTP_STATUS.ok.code, { token });
    } else {
      sendResponse(res, HTTP_STATUS.not_found.code, { code: HTTP_STATUS.not_found.code, message: HTTP_STATUS.not_found.text });
    }
  } catch (error) {
    sendResponse(res, HTTP_STATUS.internal_server_error.code, error);
  }
};

const saveUserRequest = async (req, res) => {
  try {
    const user = await daoSQL.saveUserToDB(req.body);
    if (user.length) {
      sendResponse(res, HTTP_STATUS.ok.code, user);
    } else {
      sendResponse(res, HTTP_STATUS.internal_server_error.code, { code: HTTP_STATUS.internal_server_error.code, message: HTTP_STATUS.internal_server_error.text });
    }
  } catch (error) {
    sendResponse(res, HTTP_STATUS.user_already_exist.code, error);
  }
};

module.exports = {
  findSingleUserRequest,
  authenticationRequest,
  saveUserRequest
};
