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
fastify.register(require('fastify-static'), {
  root: path.join(__dirname, 'public'),
  prefix: '/public/', // optional: default '/'
});
fastify.register(require('fastify-cors'), {
  credentials: true,
  origin: ['http://localhost:3000'],
});

fastify.get('/', async function (req, res) {
  return res.sendFile('index.html');
});

fastify.post('/register', async (req, res) => {
  let password_hash;
  const { username, password } = value;

  // generate password_hash
  try {
    password_hash = await bcrypt.hash(password, 10);
  } catch (e) {
    console.error(e);
    throw new Error("Unable to generate 'password hash'");
  }
  
});

fastify.post('/login', (req, res) => {
  // 1. validate login infos before generate jwt token
  // 2. validation success, get user infos from database
  // 3. generate jwt token with user infos
  const userInfo = {};
  const { jwtToken, jwtTokenExpiry } = auth.generateJwtToken(userInfo);

  const refreshToken = uuid.v4();

  // 4. save refresh token to database，so that we can revoke the refresh token when necessary
  const refreshTokenData = {
    // userId: user.id,
    refreshToken,
    expriedAt: dayjs().add(process.env.REFRESH_TOKEN_EXPIRES, 'minute').format('x'), // convert from minutes to milli seconds
  };

  // 5. save refreshToken token to cookie
  res.cookie('refreshToken', refreshToken, {
    maxAge: process.env.REFRESH_TOKEN_EXPIRES * 60, // convert from minute to seconds
    httpOnly: true,
    secure: false,
  });

  // 6. send jwt token to client
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
  // 4. generate jwt token with user infos
  const userInfo = {};
  const { jwtToken, jwtTokenExpiry } = auth.generateJwtToken(userInfo);

  // 5. send jwt token to client
  res.send({
    jwtToken,
    jwtTokenExpiry,
  });
});

fastify.post('/logout', async (req, res, next) => {
  // 1. remove refresh token from database
  // 2. remove refresh token from cookie

  res.cookie('refreshToken', '', {
    httpOnly: true,
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
