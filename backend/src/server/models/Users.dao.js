const { execQuery } = require('../databases/execQuery');
const bcrypt = require('bcryptjs');
const { HASHSALTSYNC } = require('../../config/constants');

const SELECT_USER_BY_EMAIL = 'SELECT * FROM usuarios WHERE email = $1;';
const INSERT_USER = 'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *;';

const findSingleUserFromDB = async (email) => await execQuery(SELECT_USER_BY_EMAIL, [email]);

const saveUserToDB = async ({ email, password, rol, lenguage }) => {
  const encryptPass = await generateHash(password);
  return await execQuery(INSERT_USER, [email, encryptPass, rol, lenguage]);
};

const isPasswordCorrect = async (email, inputPassword) => {
  const user = await findSingleUserFromDB(email);
  if (user.length < 1) return false;
  return bcrypt.compareSync(inputPassword, user[0].password);
};

const generateHash = async (password) => {
  return bcrypt.hashSync(password, HASHSALTSYNC);
};

module.exports = {
  findSingleUserFromDB,
  saveUserToDB,
  isPasswordCorrect
};
