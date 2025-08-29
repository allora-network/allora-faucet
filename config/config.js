import { stringToPath } from '@cosmjs/crypto'
import fs from 'fs'
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const mnemonic_path= "config/secret/mnemonic"
const mnemonics = [ fs.readFileSync(mnemonic_path, 'utf8').trim().split('\n')[0] ];
console.log("==================================================================")
console.log(`faucet mnemonic: ${mnemonics[0].substring(1, 15)} ...`)

export default {

    "port": 8000,  // http port
    "db": {
        "path": `./faucet.db` // db for frequency checker(WIP)
    },
    "project": {
        "name": "Testnet Faucet", // What ever you want, recommend: chain-id,
        "logo": "https://s3.amazonaws.com/assets.allora.network/logo.svg",
        "deployer": '<a href="https://allora.network">Allora</a>'
    },
    blockchains: [
    {
        name: "allora-testnet-1",
        endpoint: {
            // make sure that CORS is enabled in rpc section in config.toml
            // cors_allowed_origins = ["*"]
            rpc_endpoint: "https://allora-rpc.testnet.allora.network/",
        },
        sender: {
            mnemonics,
            option: {
                hdPaths: [stringToPath("m/44'/118'/0'/0/0")],
                prefix: "allo" // human readable address prefix
            }
        },
        tx: {
            amount: [
            { denom: "uallo", amount: "1000000000000" },
            ],
            fee: {
                amount: [{ denom: "uallo", amount: "500" }],
                gasPrice: "11uallo"
            },
        },
        limit: {
            // how many times each wallet address is allowed in a window(24h)
            address: 2,
            // how many times each ip is allowed in a window(24h),
            // if you use proxy, double check if the req.ip is return client's ip.
            ip: 20,
            cooldownInSec: 1,
            processableAddresses: 100
        }
    },
    ],
    reCaptcha: {
        siteKey: process.env.RECAPTCHA_SITE_KEY,
        secretKey: process.env.RECAPTCHA_SECRET_KEY
    },
    reCaptchaEnabled: true
}
