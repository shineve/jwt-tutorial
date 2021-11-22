const jwt = require('jsonwebtoken');
const uuid = require('uuid');
const dayjs = require('dayjs');

module.exports = {
  generateJwtToken: function (user) {
    const jwtTokenExpiry = Number(dayjs().add(process.env.JWT_TOKEN_EXPIRES, 'minute').format('x'));
    const jwtToken = jwt.sign(
      {
        jti: uuid.v4(),
        iat: Number(dayjs().format('x')), // issued at
        exp: jwtTokenExpiry, // expiration time
        // other infos
        ...user,
        // userId: user.id,
      },
      process.env.JWT_SECRET_KEY,
    );
    return {
      jwtToken,
      jwtTokenExpiry,
    };
  },
};
