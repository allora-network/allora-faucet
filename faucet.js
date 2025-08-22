import express from 'express';

import { Wallet } from '@ethersproject/wallet'
import { pathToString } from '@cosmjs/crypto';

import { BigNumber, ethers } from 'ethers'
import { bech32 } from 'bech32';

import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { SigningStargateClient } from "@cosmjs/stargate";

import conf from './config/config.js'
import { FrequencyChecker } from './checker.js';

// load config
console.log("loaded config: ", conf)

const app = express()

// Middleware to parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('static'));

app.set("view engine", "ejs");

const checker = new FrequencyChecker(conf)

app.use((req, res, next) => {
  const clientip = req.headers['x-real-ip'] || req.headers['X-Real-IP'] || req.headers['X-Forwarded-For'] || req.ip
  console.log(`Received ${req.method} request at ${req.url} from ${clientip}`);
  next();
});

app.get('/', (req, res) => {
  res.render('index', conf);
})

app.get('/config.json', async (req, res) => {
  const sample = {};
  for (let i = 0; i < conf.blockchains.length; i++) {
    const chainConf = conf.blockchains[i];
    const addresses = [];

    for (const mnemonic of chainConf.sender.mnemonics) {
      const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, chainConf.sender.option);
      const [firstAccount] = await wallet.getAccounts();
      addresses.push(firstAccount.address);
    }

    sample[chainConf.name] = addresses;
  }

  const project = conf.project;
  project.sample = sample;
  project.blockchains = conf.blockchains.map(x => x.name);
  project.addressPrefix = conf.blockchains[0].sender.option.prefix;
  project.reCaptchaSiteKey = conf.reCaptcha.siteKey;
  res.send(project);
});

const queue = [];
const addressStatus = {};
let mnemonicCounter = 0;

// Enqueue address
const enqueueAddress = async (statusAddress) => {
  console.log('Enqueueing address:', statusAddress);
  if (!addressStatus[statusAddress] || addressStatus[statusAddress] === 'cleared') {
    if (!queue.includes(statusAddress)) {
      queue.push(statusAddress);
    }
  }
};

// Process addresses
const processAddresses = async (chain) => {
  console.log('Starting to process addresses'); 

  while (true) {
    console.log(`The length of the queue: ${queue.length}`);
    
    if (queue.length > 0) {
      const addressesToProcess = [];
      for (let i = 0; i < conf.blockchains[0].limit.processableAddresses && queue.length > 0; i++) {
        const statusAddress = queue.shift();
        const address = statusAddress.replace('status:', '');
        addressesToProcess.push(address);
      }
      
      try {
        await sendCosmosTx(addressesToProcess, chain)
        addressesToProcess.forEach(address => {
          const statusAddress = `status:${address}`;
          addressStatus[statusAddress] = 'Completed';
        });
      } catch (error) {
        console.log(error, 'error');
      }
    }

    console.log(`Waiting for ${conf.blockchains[0].limit.cooldownInSec} seconds cooldown period`);
    const cooldownTime = conf.blockchains[0].limit.cooldownInSec * 1000;
    await new Promise(resolve => setTimeout(resolve, cooldownTime));
  }
};

processAddresses(conf.blockchains[0].name);

app.get('/balance/:chain', async (req, res) => {
  const { chain } = req.params;
  let balances = [];

  try {
    const chainConf = conf.blockchains.find(x => x.name === chain);
    if (chainConf) {
      const rpcEndpoint = chainConf.endpoint.rpc_endpoint;

      for (const mnemonic of chainConf.sender.mnemonics) {
        const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, chainConf.sender.option);
        const client = await SigningStargateClient.connectWithSigner(rpcEndpoint, wallet);
        const [firstAccount] = await wallet.getAccounts();
        
        const balance = await client.getBalance(firstAccount.address, chainConf.tx.amount[0].denom);
        balances.push({
          address: firstAccount.address,
          balance: balance
        });
      }
    }
  } catch (err) {
    console.log(err);
  }
  res.send(balances);
});

const blocklist = new Set();
const ipCounter = new Map();
const TIME_WINDOW = 60000; // 1 minute in milliseconds
const MAX_REQUESTS = 3; // Threshold for blocklisting

// API key rate limiting
const apiKeyCounter = new Map();
const API_KEY_TIME_WINDOW = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
const MAX_API_KEY_REQUESTS = 3; // Maximum requests per API key per day

const checkIpBlockList = async (ip) => {
    const [firstOctet, secondOctet] = ip.split('.');
    const ipPrefix = `${firstOctet}.${secondOctet}`;

    // Check if the IP prefix is in the blocklist
    if (blocklist.has(ipPrefix)) {
      return true
    }

    const now = Date.now();

    // Check and update IP counter
    if (!ipCounter.has(ipPrefix)) {
        ipCounter.set(ipPrefix, []);
    }

    const timestamps = ipCounter.get(ipPrefix);
    timestamps.push(now);

    // Remove timestamps older than 1 minute
    while (timestamps.length > 0 && now - timestamps[0] > TIME_WINDOW) {
        timestamps.shift();
    }

    // If more than 3 requests in the last minute, add to blocklist
    if (timestamps.length > MAX_REQUESTS) {
      blocklist.add(ipPrefix);
      ipCounter.delete(ipPrefix);
    } else {
        ipCounter.set(ipPrefix, timestamps);
    }

    return false
};

const checkApiKeyRateLimit = async (apiKey) => {
    const now = Date.now();
    
    // Check and update API key counter
    if (!apiKeyCounter.has(apiKey)) {
        apiKeyCounter.set(apiKey, []);
    }
    
    const timestamps = apiKeyCounter.get(apiKey);
    
    // Remove timestamps older than 24 hours
    while (timestamps.length > 0 && now - timestamps[0] > API_KEY_TIME_WINDOW) {
        timestamps.shift();
    }
    
    // Check if API key has exceeded daily limit
    if (timestamps.length >= MAX_API_KEY_REQUESTS) {
        return false; // Rate limit exceeded
    }
    
    // Add current timestamp
    timestamps.push(now);
    apiKeyCounter.set(apiKey, timestamps);
    
    return true; // Request allowed
};

app.post('/api/request', async (req, res, next) => {
  try {
    const {chain, address} = req.body;
    const apiKey = req.headers['x-api-key'];
    
    // Check for API key header - if present, skip captcha
    if (!apiKey) {
        console.log('api key missing')
      return res.status(401).json({ code: 1, message: 'API key required' });
    }
    
    // Check API key rate limit (3 requests per day)
    const rateLimitAllowed = await checkApiKeyRateLimit(apiKey);
    if (!rateLimitAllowed) {
        console.log('rate limit')
      return res.status(429).json({ 
        code: 1, 
        message: `API key rate limit exceeded. Maximum ${MAX_API_KEY_REQUESTS} requests per 24 hours.` 
      });
    }
    
    // Optional: Add API key validation here if needed
    // if (apiKey !== conf.apiKey) {
    //   return res.status(401).json({ code: 1, message: 'Invalid API key' });
    // }

    // Process request
    const ip = req.headers['x-real-ip'] || req.headers['X-Real-IP'] || req.headers['X-Forwarded-For'] || req.ip
    console.log('request tokens to ', address, ip)
    if (chain || address ) {
      // try {
        const chainConf = conf.blockchains.find(x => x.name === chain)
        if (chainConf && (address.startsWith(chainConf.sender.option.prefix) || address.startsWith('0x'))) {
          if( await checker.checkAddress(address, chain) && await checker.checkIp(`${chain}${ip}`, chain) ) {
            checker.update(`${chain}${ip}`) // get ::1 on localhost

            const statusAddress = `status:${address}`;
            if (addressStatus[statusAddress] === 'Completed') {
              addressStatus[statusAddress] = 'cleared';
                console.log('cleared')
              return res.status(201).json({ code: 0, message: 'Your previous faucet request has been processed. You can now submit a new request.' });
            }

            if (queue.includes(statusAddress)) {
                console.log('already in queue')
              console.log('Address already in queue');
              return res.status(200).json({ code: 0, message: 'Address already in the processing queue' });
            }

            const ipBlocked = await checkIpBlockList(ip);
            if (ipBlocked) {
              console.log(`IP blocked - ${ip}`);
              return res.status(403).json({ code: 1, message: `IP added to blocklist.`});
            }
            
            await enqueueAddress(statusAddress);
            console.log('address enqueued')
            await checker.update(address)
            return res.status(201).json({ code: 0, message: 'Address enqueued for faucet processing.' });

          }else {
            console.log('2 many requests')
            return res.status(429).json({ code: 1, message: `Too many faucet requests sent for address '${address}'. Try again later.
              \nLimits per 24h: ${chainConf.limit.address} times per address, ${chainConf.limit.ip} times per IP.
            `})
          }
        } else {
          console.log('address not supported')
          return res.status(400).json({ code: 1, message: `Address '${address}' is not supported.`, recipient: address })
        }
      // } catch (err) {
      //   console.error(err);
      //   res.send({ result: 'Failed, Please contact to admin.' })
      // }

    } else {
      // send result
      console.log('addy required')
      return res.status(400).json({ code: 0, message: 'address is required' });
    }
  } catch (error) {
    console.error('API send error:', error);
    return res.status(500).json({ code: 1, message: 'Internal server error' });
  }
})

app.post('/send', async (req, res, next) => {
  return Promise.resolve().then(async () => {
    const {chain, address, recapcha_token} = req.body;
    if (conf.reCaptchaEnabled) {
      // Verify recaptcha
      const recaptchaVerification = await getRecaptchaVerification(recapcha_token);
      console.log('recaptchaVerification response:', JSON.stringify(recaptchaVerification, null, 2));
      if (!recaptchaVerification.success) {
        return res.status(401).json({ code: 1, message: 'Recaptcha verification failed' });
      }
    }

    // Process request
    const ip = req.headers['x-real-ip'] || req.headers['X-Real-IP'] || req.headers['X-Forwarded-For'] || req.ip
    console.log('request tokens to ', address, ip)
    if (chain || address ) {
      // try {
        const chainConf = conf.blockchains.find(x => x.name === chain)
        if (chainConf && (address.startsWith(chainConf.sender.option.prefix) || address.startsWith('0x'))) {
          if( await checker.checkAddress(address, chain) && await checker.checkIp(`${chain}${ip}`, chain) ) {
            checker.update(`${chain}${ip}`) // get ::1 on localhost

            const statusAddress = `status:${address}`;
            if (addressStatus[statusAddress] === 'Completed') {
              addressStatus[statusAddress] = 'cleared';
              return res.status(201).json({ code: 0, message: 'Your previous faucet request has been processed. You can now submit a new request.' });
            }

            if (queue.includes(statusAddress)) {
              console.log('Address already in queue');
              return res.status(200).json({ code: 0, message: 'Address already in the processing queue' });
            }

            const ipBlocked = await checkIpBlockList(ip);
            if (ipBlocked) {
              console.log(`IP blocked - ${ip}`);
              res.status(403).json({ code: 1, message: `IP added to blocklist.`});
            } else {
              await enqueueAddress(statusAddress);
              res.status(201).json({ code: 0, message: 'Address enqueued for faucet processing.' });
            }

            await checker.update(address)

          }else {
            res.status(429).send({ code: 1, message: `Too many faucet requests sent for address '${address}'. Try again later.
              \nLimits per 24h: ${chainConf.limit.address} times per address, ${chainConf.limit.ip} times per IP.
            `})
          }
        } else {
          res.status(400).send({ code: 1, message: `Address '${address}' is not supported.`, recipient: address })
        }
      // } catch (err) {
      //   console.error(err);
      //   res.send({ result: 'Failed, Please contact to admin.' })
      // }

    } else {
      // send result
      res.status(400).send({ code: 0, message: 'address is required' });
    }}).catch(next)
})

// 500 - Any server error
app.use((err, req, res, next) => {
  console.log("\nError caught by middleware:", err);
  if (!res.headersSent) {
    res.status(500).json({ code: 1, message: 'Internal server error' });
  }
})

app.listen(conf.port, () => {
  console.log(`Faucet app listening on port ${conf.port}`)
})

async function getRecaptchaVerification(token) {
  const secret = conf.reCaptcha.secretKey;
  console.log("Fetching recaptcha verification:", `https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${token}`)
  const response = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${token}`, {
    method: 'POST',
  });
  return response.json();
}

async function sendCosmosTx(recipients, chain) {
  console.log("sendCosmosTx", recipients, chain);

  const chainConf = conf.blockchains.find(x => x.name === chain);
  if (chainConf) {
    // Get the mnemonic to use and update the counter
    const mnemonic = chainConf.sender.mnemonics[mnemonicCounter];
    mnemonicCounter = (mnemonicCounter + 1) % chainConf.sender.mnemonics.length;

    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, chainConf.sender.option);
    const [firstAccount] = await wallet.getAccounts();
    console.log(`using faucet ${firstAccount.address}`);

    const rpcEndpoint = chainConf.endpoint.rpc_endpoint;
    const client = await SigningStargateClient.connectWithSigner(rpcEndpoint, wallet, { gasPrice: chainConf.tx.fee.gasPrice });
    const amount = chainConf.tx.amount;

    const messages = recipients.map(recipient => ({
      typeUrl: "/cosmos.bank.v1beta1.MsgSend",
      value: {
        fromAddress: firstAccount.address,
        toAddress: recipient,
        amount: amount,
      },
    }));
    // console.log('stringMessage:', JSON.stringify(messages));

    try {
      const txResult = await client.signAndBroadcast(firstAccount.address, messages, "auto");
      
      if (txResult.code !== 0) {
        throw new Error(`Transaction failed with code ${txResult.code}: ${txResult.rawLog}`);
      }
      
      console.log(`Sent ${amount[0].amount}${amount[0].denom} tokens to ${recipients.length} addresses`);
      return {code: 0};
      
    } catch (e) {
      throw new Error(`Failed to send tokens. Error: ${e.message}`);
    }
  }
  
  throw new Error(`Blockchain Config [${chain}] not found`);
}

async function sendEvmosTx(recipient, chain) {

  try{
    const chainConf = conf.blockchains.find(x => x.name === chain)
    const ethProvider = new ethers.providers.JsonRpcProvider(chainConf.endpoint.evm_endpoint);

    const wallet = Wallet.fromMnemonic(chainConf.sender.mnemonic).connect(ethProvider);

    let evmAddress =  recipient;
    if(recipient && !recipient.startsWith('0x')) {
      let decode = bech32.decode(recipient);
      let array = bech32.fromWords(decode.words);
      evmAddress =  "0x" + toHexString(array);
    }

    let result = await wallet.sendTransaction(
        {
          from:wallet.address,
          to:evmAddress,
          value:chainConf.tx.amount.amount
        }
      );

    let repTx = {
      "code":0,
      "nonce":result["nonce"],
      "value":result["value"].toString(),
      "hash":result["hash"]
    };

    console.log("xxl result : ",repTx);
    return repTx;
  }catch(e){
    console.log("xxl e ",e);
    return e;
  }

}

function toHexString(bytes) {
  return bytes.reduce(
      (str, byte) => str + byte.toString(16).padStart(2, '0'),
      '');
}

// write a function to send evmos transaction
async function sendEvmosTx2(recipient, chain) {

  // use evmosjs to send transaction
  const chainConf = conf.blockchains.find(x => x.name === chain)
  // create a wallet instance
  const wallet = Wallet.fromMnemonic(chainConf.sender.mnemonic).connect(chainConf.endpoint.evm_endpoint);
}
