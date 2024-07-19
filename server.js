require('dotenv').config()

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')

app.use(express.json())

const users = []

app.post('/signup',async (req, res) =>{
  const existingUser = users.find(user => user.name === req.body.name);
  if (existingUser) {
      return res.send('User already exists');
  }
  const hashedPassword = await bcrypt.hash(req.body.password, 10)
  const user = { name: req.body.name, password: hashedPassword }
  users.push(user)
  res.send('success')
})

app.post('/login', async(req, res) => {
    const user = users.find(user => user.name === req.body.name);
    if (user == null) {
        return res.status(400).send('Cannot find user');
    }
    if(await bcrypt.compare(req.body.password, user.password)) {
        const accessToken = generateAccessToken(user)
        res.json({ accessToken: accessToken})
    } else {
        res.send('Not Allowed');
    }
});

app.get('/protected', authenticateToken, (req, res) => {
    res.send('welcome')
  })
  
  function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)
  
    jwt.verify(token,process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      console.log(err)
      if (err) return res.send('denied')
      req.user = user
      next()
    })
  }

function generateAccessToken(user) {
    return jwt.sign(user,process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
  }

app.listen(3000, () => {
    console.log('Server running on port 3000')
});
