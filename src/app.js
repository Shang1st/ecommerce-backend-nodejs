require('dotenv').config()
const compression = require('compression')
const express = require('express')
const { default: helmet } = require('helmet')
const morgan = require('morgan')
const app = express()

// int middlewares
app.use(morgan("dev"))
app.use(helmet())
app.use(compression())

// int db
require('./dbs/init.mongodb')

// int routes
app.get('/', (req, res, next) => {
    const strCompress = 'Hello Fan!'
    return res.status(200).json({
        message: 'Welcome Fans!',
        // metadata: strCompress.repeat(100000)
    })
})

module.exports = app