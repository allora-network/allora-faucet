import { Level } from "level";

const WINDOW = 86400 * 1000 // milliseconds in a day
// const WINDOW = 20 * 1000 // 20s for test

export class FrequencyChecker {
    constructor(conf) {
        this.conf = conf
        this.db = new Level(conf.db.path, { valueEncoding: 'json' });
    }

    async check(key, limit) {
        return new Promise((resolve) => {
            this.db.get(key, function (err, value) {
                const now = Date.now()
                if (err || value && value.filter(x => now - x < WINDOW).length < limit) {
                    resolve(true)
                    // console.log(key, limit, value, true)
                } else {
                    resolve(false)
                    // console.log(key, limit, false)
                }
            });
        })
    }

    async checkIp(ip, chain) {
        const chainLimit = this.conf.blockchains.find(x => x.name === chain)
        return chainLimit ? this.check(ip, chainLimit.limit.ip ) : Promise.resolve(false)
    }

    async checkAddress(address, chain) {
        const chainLimit = this.conf.blockchains.find(x => x.name === chain)
        return chainLimit ? this.check(address, chainLimit.limit.address ) : Promise.resolve(false)
    }

    async update(key) {
        const db = this.db
        db.get(key, function (err, history) {
            if (err) {
                db.put(key, [Date.now()])
            } else {
                history.push(Date.now())
                db.put(key, history)
            }
        });
    }

    async updateRequestStatus(requestId, status, message, data=null) {
        const db = this.db
        let request
        try {
            request = await db.get(requestId)
            request.statuses.push(status)
        } catch (error) {
            if (error.status == 404) {
                request = {statuses: [status]}
            } else {
                console.log(error, 'error')
            }
        }
        await db.put(requestId, {data, statuses: request.statuses, messsage: message ? message : ''});
    }

    async getRequestStatus(requestId) {
        const db = this.db
        const request = await db.get(requestId);
        return request
    }

    async put(key, value) {
        await this.db.put(key, value)
    }

    async get (address) {
        try {
            const status = await this.db.get(address);
            return status
        } catch (err) {
            if (err.notFound) {
                console.log('Address not found')
            } else {
                console.log('Database error')
            }
        }
    }
}
