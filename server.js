require('dotenv').config();
const app = require("./src/app");

const PORT = process.env[process.env.NODE_ENV === 'pro' ? 'PRO_APP_PORT' : 'DEV_APP_PORT'] || 3056

const server  = app.listen(PORT, () => {
    console.log(`WSV eCommerce start with ${PORT}`)
})

// process.on('SIGINT', () => {
//     server.close( () => console.log(`Exit Server Express`))
// })