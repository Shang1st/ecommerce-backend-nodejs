'use strict'

const shopModel = require("../models/shop.model")
const bcrypt = require('bcrypt')
const crypto = require('node:crypto')
const KeyTokenService = require("./keyToken.service")
const { createTokenPair } = require("../auth/authUtils")
const { getInfoData } = require("../utils")
const { ceil } = require("lodash")
const { BadRequestError, AuthFailureError } = require("../core/error.response")
const { findByEmail } = require("./shop.service")

const RoleShop = {
    SHOP: 'SHOP',
    WRITER: 'WRITER',
    EDITOR: 'EDITOR',
    ADMIN: 'ADMIN'
}

class AccessService {

    static login  = async( { email, password, refreshToken = null}) => {
        //.1
        const foundShop = await findByEmail(email)
        if(!foundShop) throw new BadRequestError('Shop not registered')
        //.2
        const match = bcrypt.compare(password, foundShop.password)
        if(!match) throw new AuthFailureError('Authentication error')
        //.3
        const privateKey = crypto.randomBytes(64).toString('hex')
        const publicKey = crypto.randomBytes(64).toString('hex') 
        //.4
        const { _id: userId } = foundShop
        const tokens = await createTokenPair({ userId, email}, publicKey, privateKey)

        await KeyTokenService.createKeyToken({
            refreshToken: tokens.refreshToken,
            privateKey, publicKey, userId: foundShop._id
        })

        return {
            shop: getInfoData({ fileds: ['_id', 'name', 'email'], object: foundShop}),
            tokens
        }
    }

    static signUp = async ({ name, email, password }) => {
            
            // step1: check email exists ?
            const hodelShop = await shopModel.findOne({ email }).lean()
            if(hodelShop){
                throw new BadRequestError('Error: Shop already registered')
            }

            const passwordHash = await bcrypt.hash(password, 10)

            const newShop = await shopModel.create({
                name, email, password: passwordHash, roles: [RoleShop.SHOP]
            })

            if(newShop){
                //created privateKey, publicKey
                const privateKey = crypto.randomBytes(64).toString('hex')
                const publicKey = crypto.randomBytes(64).toString('hex') 
                // Public key CryptoGraphy Standrds !

                console.log({privateKey, publicKey}) // save collection KeyStore

                const keyStore = await KeyTokenService.createKeyToken({
                    userId: newShop._id,
                    publicKey,
                    privateKey
                })
                
                if(!keyStore){
                    return {
                        code: 'xxxx',
                        message: 'keyStore error'
                    }
                }

                // created toke pair
                const tokens = await createTokenPair({userId: newShop._id, email}, publicKey, privateKey)
                console.log(`Created Token Success::`, tokens)

                return {
                    code: 201,
                    metadata: {
                        shop: getInfoData({ fileds: ['_id', 'name', 'email'], object: newShop}),
                        tokens
                    }
                }
            }

            return {
                code: 200,
                metadata: null
            }

    }
}

module.exports = AccessService