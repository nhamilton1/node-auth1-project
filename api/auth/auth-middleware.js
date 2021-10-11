const User = require('../users/users-model')
const bcrypt = require('bcryptjs')

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  if(req.session.user) {
    next()
  } else {
    next({
      message: `invalid credentials`,
      status: 401
    })
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {
  try {
    const { username } = req.body
    const user = await User.findBy({ username }).first()
    if (!user) {
      next()
    }
  } catch (err) {
    next({
      status: 422,
      message: "Username taken"
    })
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req, res, next) {
  try {
    const { username, password } = req.body
    const user = await User.findBy({ username }).first()
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user
      res.status(200).json({ message: `welcome back ${user.username}` })
    }
  } catch (err) {
    next({
      status: 401,
      message: "Invalid credentials"
    })
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
async function checkPasswordLength(req, res, next) {
  try {
    const { password } = req.body
    if (password.length < 3) {
      next()
    }
  } catch (err) {
    next({
      status: 422,
      message: "Password must be longer than 3 chars"
    })
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
}