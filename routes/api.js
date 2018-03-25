const express = require('express')
const expressSession = require('express-session')
const passport = require('passport')
const verifyJwt = require('express-jwt')

const auth = require('../lib/auth.js')

const router = express.Router()
router.use(express.json())

// The only thing we need sessions for is the Twitter strategy, because it's OAuth 1a
const session = expressSession({
  resave: false,
  saveUninitialized: false,
  secret: process.env.SESSION_SECRET
})

// This is the only API route that uses Twitter strategy,
// to check if we can issue a JWT in response to requests.
router.get('/auth/twitter', session, passport.authenticate('twitter'))
router.get('/auth/twitter/callback', session, auth.issueJwt)
router.get('/auth/logout', (req, res) => {
  res.clearCookie('token', { path: '/' })
  res.json({ message: 'User logged out.' })
})

// express-jwt middleware lets us use a function as the secret,
// so we can grab it out of app settings
function getSecret (req, payload, done) {
  done(null, req.app.get('JWT_SECRET'))
}

// This route will set the req.user object if it exists, but is still public
router.get('/open',
  verifyJwt({
    credentialsRequired: false,
    getToken: auth.getToken,
    secret: getSecret
  }),
  (req, res) => {
    const json = { message: 'This route is public.' }
    if (req.user) {
      json.user = `Your user ID is: ${req.user.id}`
    }
    res.json(json)
  }
)

// Protect all routes beneath this point
router.use(
  verifyJwt({
    getToken: auth.getToken,
    secret: getSecret
  }),
  auth.handleError
)

// These routes are protected
router.get('/closed', (req, res) => {
  res.json({ message: `Yup, you seem to be user ${req.user.id}.` })
})

module.exports = router
