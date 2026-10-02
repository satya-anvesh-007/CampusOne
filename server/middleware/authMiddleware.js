const jwt = require('jsonwebtoken')
const { getJwtSecret } = require('../config')

const protect = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        message: 'No token provided'
      })
    }

    const token = authHeader.split(' ')[1]

    const decoded = jwt.verify(token, getJwtSecret())

    req.userId = decoded.userId

    next()
  } catch (error) {
    if (error.message === 'JWT_SECRET is not configured') {
      return res.status(503).json({
        message: 'Authentication service is not configured'
      })
    }

    return res.status(401).json({
      message: 'Invalid or expired token'
    })
  }
}

module.exports = protect