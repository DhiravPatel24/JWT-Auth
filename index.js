const express = require('express')
const cookieParser = require('cookie-parser')
const mongoose = require('mongoose')
require('dotenv').config();
const authRoutes = require('./routes/authRoutes.js')
const {requireAuth, checkUser} = require('./middlewares/authMiddlewares.js')
const app = express()

app.use(express.json())
app.use(express.static('public'))
app.use(cookieParser())
app.use(authRoutes)
app.set('view engine', 'ejs');

const dbURI = process.env.DB_URI

mongoose.connect(dbURI,{ 
}).then((result)=>{
    console.log('connection successfull ...')
    app.listen(3000)
}).catch((err)=> console.log(err))

app.get('*',checkUser)

app.get('/',(req,res)=>{
    res.render('login')
})

app.get('/logout', (req, res) => {

    res.clearCookie('jwt');
    res.redirect('/login');
});

app.get('/dashboard', requireAuth,(req,res)=>{
    res.render('dashboard')
})
