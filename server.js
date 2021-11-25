const fastify = require('fastify')();
const cookie = require('fastify-cookie');
const path = require('path');
const uuid = require('uuid');
const jwt = require('jsonwebtoken');
const dayjs = require('dayjs');
dayjs.extend(require('dayjs/plugin/advancedFormat'));
dayjs().format('x');

const auth = require('./auth');

require('dotenv').config();

fastify.register(cookie, { secret: process.env.SECRET_KEY });

fastify.get('/', async function (req, res) {
  return res.sendFile('index.html');
});

fastify.get('/api/test', async function (req, res) {
  const token = req.cookies.jwt;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    return res.send(decoded);
  } catch (err) {
    return res.status(401).send('Unauthorized');
  }
});

fastify.post('/login', (req, res) => {
  // 1. validate login infos before generate jwt token
  // 2. validation success, get user infos from database

  // 3. generate jwt token with user infos
  const userInfo = {};
  // 4. generate jwt token with user infos
  const { jwtToken, jwtTokenExpiry } = auth.generateJwtToken(userInfo);

  // 5. generate and save refresh token to database，so that we can revoke the refresh token when necessary
  const refreshToken = uuid.v4();
  const refreshTokenData = {
    // userId: user.id,
    refreshToken,
    expriedAt: dayjs().add(process.env.REFRESH_TOKEN_EXPIRES, 'minute').format('x'), // convert from minutes to milli seconds
  };

  // 6. set refresh token to client's cookie
  res.setCookie('refreshToken', refreshToken, {
    maxAge: process.env.REFRESH_TOKEN_EXPIRES * 60, // convert from minute to seconds
    httpOnly: true,
    secure: false,
  });

  // 7. set jwt token to client's cookie
  res.setCookie('jwt', jwtToken, {
    maxAge: process.env.JWT_TOKEN_EXPIRES * 60, // convert from minute to seconds
    httpOnly: true,
    secure: false,
  });

  // 8. send jwt token to client
  res.send({
    jwtToken,
    jwtTokenExpiry,
  });
});

fastify.post('/refresh-token', async (req, res, next) => {
  const refreshTokenId = req.cookies.refreshToken;
  // 1. check if refresh token exist in database
  // 2. check if refresh token is valid

  // 3. retrive user data from database
  const userInfo = {};
  // 4. generate jwt token with user infos
  const { jwtToken, jwtTokenExpiry } = auth.generateJwtToken(userInfo);

  // 5. set jwt token to client's cookie
  res.setCookie('jwt', jwtToken, {
    maxAge: process.env.JWT_TOKEN_EXPIRES * 60, // convert from minute to seconds
    httpOnly: true,
    secure: false,
  });

  // 6. send jwt token to client
  res.send({
    jwtToken,
    jwtTokenExpiry,
  });
});

fastify.post('/logout', async (req, res, next) => {
  // 1. remove refresh token from database / add refresh token to revoked list
  // 2. remove refresh token from client's cookie

  // 3. set refresh token to client's cookie
  res.setCookie('refreshToken', '', {
    httpOnly: true,
    maxAge: 0,
  });

  // 4. set jwt token to client's cookie
  res.setCookie('jwt', '', {
    maxAge: process.env.JWT_TOKEN_EXPIRES * 60, // convert from minute to seconds
    maxAge: 0,
  });

  res.send('OK');
});

// Run the server!
const start = async () => {
  const port = process.env.PORT || 3000;
  try {
    await fastify.listen(port);
    console.log(`Example app listening at http://localhost:${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();
