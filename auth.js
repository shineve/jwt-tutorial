const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const dayjs = require('dayjs')

export const generateJwtToken = function(user) {
  const jwtTokenExpiry = Number(
    dayjs()
      .add(JWT_TOKEN_EXPIRES, 'minute')
      .format('x'),
  )
  const jwtToken = jwt.sign(
    {
      jti: uuid.v4(),
      iat: Number(dayjs().format('x')), // issued at
      exp: jwtTokenExpiry, // expiration time
      ...user,
    },
    JWT_SECRET_KEY,
  )
  return {
    jwtToken,
    jwtTokenExpiry,
  }
}
