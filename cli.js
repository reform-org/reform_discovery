import readline from "readline";
import bcrypt from "bcrypt";
import { db } from "./db.js";
import { v4 as uuidv4 } from 'uuid';

db.init()

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const ask = (question) => new Promise(resolve => {
    rl.question(`${question} `, resolve);
});

const done = () => {
    process.exit(0);
};

(async () => {
    const username = await ask("Please enter a username:");
    const password = await ask("Please enter a password:");
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, (err, hash) => {
            db.instance.run("INSERT OR REPLACE INTO users (name, uuid, password) VALUES(?, ?, ?)", username, uuidv4(), hash, done);
        })
    })
})()