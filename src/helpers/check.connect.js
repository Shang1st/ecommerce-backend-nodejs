'use strict'

const mongoose = require('mongoose')
const countConnect = () => {
    const numConnection = mongoose.connections.length
    
}

module.exports = {
    countConnect
}