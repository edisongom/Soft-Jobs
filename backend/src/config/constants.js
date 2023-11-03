const HTTP_STATUS = {
  ok: { code: 200 },
  created: { code: 201 },
  unauthorized: {
    code: 401,
    text: {
      op1: 'There is no token to validate.',
      op2: 'Invalid token format.',
      op3: 'Invalid token.'
    }
  },
  not_found: { code: 404, text: 'Resource not found.' },
  incorrect_pasword: { code: 401, text: 'Incorrect pasword.' },
  user_already_exist: { code: 401, text: 'User already exist.' },
  internal_server_error: { code: 500, text: 'Internal server error.' }
}

const HASHSALTSYNC = 8

module.exports = { HTTP_STATUS, HASHSALTSYNC }