import dayjs from 'dayjs';
import jwt from 'jsonwebtoken';
import { parse, serialize } from 'cookie';
import { Router } from 'itty-router';
import { v4 as uuidv4 } from 'uuid';
import { generateJwtToken } from './auth';

dayjs.extend(require('dayjs/plugin/advancedFormat'));
dayjs().format('x');

const router = Router();

router
  .get('/token-info', getUserInfo)
  .post('/login', loginUser)
  .post('/logout', logoutUser)
  .get('/refresh-token', getNewAccessToken)
  .get('*', () => new Response('Not found', { status: 404 }));

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
/**
 * Respond with hello worker text
 * @param {Request} request
 */
async function handleRequest(request) {
  return router.handle(request);
}

function loginUser(request) {
  // 1. validate login infos before generate jwt token
  // 2. validation success, get user infos from database

  // 3. generate jwt token with user infos
  const userInfo = {};
  // 4. generate jwt token with user infos
  const { jwtToken, jwtTokenExpiry } = generateJwtToken(userInfo);

  // 5. generate and save refresh token to database，so that we can revoke the refresh token when necessary
  const refreshToken = uuidv4();
  const refreshTokenData = {
    // userId: user.id,
    refreshToken,
    expriedAt: dayjs()
      .add(REFRESH_TOKEN_EXPIRES, 'minute')
      .format('x'), // convert from minutes to milli seconds
  };

  const response = new Response(
    JSON.stringify({
      jwtToken,
      jwtTokenExpiry,
    }),
    {
      headers: {
        'content-type': 'application/json;charset=UTF-8',
      },
    },
  );

  // 6. set refresh token to client's cookie
  response.headers.append(
    'Set-Cookie',
    serialize('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: REFRESH_TOKEN_EXPIRES * 60,
    }),
  );

  // 7. set jwt token to client's cookie
  response.headers.append(
    'Set-Cookie',
    serialize('jwt', jwtToken, {
      httpOnly: true,
      maxAge: JWT_TOKEN_EXPIRES * 60,
    }),
  );

  // 8. send jwt token to client
  return response;
}

function logoutUser(request) {
  // 1. remove refresh token from database / add refresh token to revoked list
  // 2. remove refresh token from client's cookie
  const response = new Response('OK');

  // 3. set refresh token to client's cookie
  response.headers.append(
    'Set-Cookie',
    serialize('refreshToken', '', {
      httpOnly: true,
      maxAge: 0,
    }),
  );

  // 4. set jwt token to client's cookie
  response.headers.append(
    'Set-Cookie',
    serialize('jwt', '', {
      httpOnly: true,
      maxAge: 0,
    }),
  );

  return response;
}

function getUserInfo(request) {
  const cookie = parse(request.headers.get('Cookie') || '');
  const jwtToken = cookie.jwt || '';

  if (!jwtToken) {
    return new Response('No jwt token', { status: 401 });
  }

  try {
    const decoded = jwt.verify(jwtToken, JWT_SECRET_KEY);
    return new Response(JSON.stringify(decoded), {
      headers: {
        'content-type': 'application/json;charset=UTF-8',
      },
    });
  } catch (err) {
    return new Response(err, { status: 401 });
  }
}

function getNewAccessToken(request) {
  const cookie = parse(request.headers.get('Cookie') || '');
  const refreshToken = cookie.refreshToken || '';
  // 1. check if request have refreshToken
  if (!refreshToken) {
    return new Response('No refresh token', { status: 401 });
  }
  // 2. check if refresh token exist in database
  // 3. check if refresh token is valid

  // 4. retrive user data from database
  const userInfo = {};
  // 5. generate jwt token with user infos
  const { jwtToken, jwtTokenExpiry } = generateJwtToken(userInfo);

  const response = new Response(
    JSON.stringify({
      jwtToken,
      jwtTokenExpiry,
    }),
    {
      headers: {
        'content-type': 'application/json;charset=UTF-8',
      },
    },
  );

  // 6. set jwt token to client's cookie
  response.headers.append(
    'Set-Cookie',
    serialize('jwt', jwtToken, {
      httpOnly: true,
      maxAge: JWT_TOKEN_EXPIRES * 60,
    }),
  );

  // 7. send jwt token to client
  return response;
}
