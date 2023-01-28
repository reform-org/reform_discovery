import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import { db } from "./db.js";
import cors from "cors";
import { authenticateToken } from "./middleware.js";
import { WebSocketServer } from "ws";
// import { createServer } from 'https';
import { createServer } from 'http';
import { readFileSync } from 'fs';
import { v4 as uuidv4 } from 'uuid';

dotenv.config();

const app = express();
const port = 3000;

const error = (message) => {
    return {
        error: {
            message
        }
    };
};

app.use(bodyParser.json());
app.use(cors());

app.post("/api/login", async (req, res) => {
    const username = req.body?.username;
    const password = req.body?.password;

    if (!username || !password) return res.status(400).json(error("Username and password must not be empty!"));

    const userEntry = await db.get("SELECT * FROM users WHERE name = ?", username);

    if (!userEntry) return res.status(404).json(error(`The user "${username}" does not exist. Please contact your admin to add the user manually.`));

    if (!bcrypt.compareSync(password, userEntry.password)) return res.status(401).json(error(`The password for the user "${username}" is wrong.`));

    const token = jwt.sign({ username, uuid: userEntry.uuid }, process.env.JWT_KEY, { expiresIn: '14d' }); // 14 days
    res.json({ username, token });
});

app.post("/api/available", authenticateToken, async (req, res) => {
    db.instance.run("UPDATE users SET online = TRUE WHERE uuid = ?", req.user.uuid);
    res.status(202).send();
});

app.post("/api/whitelist/trust", authenticateToken, async (req, res) => {
    const uuid = req.body.user?.uuid;
    if (!uuid) return res.status(400).json(error("Please specify a uuid."));
    const userEntry = await db.get("SELECT * FROM users WHERE uuid = ?", uuid);
    if (!userEntry) return res.status(404).json(error(`The user with the uuid "${uuid}" does not exist. Please contact your admin to add the user manually.`));

    db.instance.run("INSERT INTO trust(a, b) VALUES (?, ?)", req.user.id, userEntry.id);
    res.status(202).send();
});

app.post("/api/whitelist/revoke", authenticateToken, async (req, res) => {
    const uuid = req.body.user?.uuid;
    if (!uuid) return res.status(400).json(error("Please specify a uuid."));
    const userEntry = await db.get("SELECT * FROM users WHERE uuid = ?", uuid);
    if (!userEntry) return res.status(404).json(error(`The user with the uuid "${uuid}" does not exist. Please contact your admin to add the user manually.`));

    db.instance.run("DELETE FROM trust WHERE a = ? AND b = ?", req.user.id, userEntry.id);
    res.status(202).send();
});

app.get("/api/clients", authenticateToken, async (req, res) => {
    const clients = await db.all("SELECT name, uuid, online, EXISTS(SELECT * FROM trust WHERE a = ? AND b = id) as trusted FROM users WHERE NOT id = ?", req.user.id, req.user.id);
    res.status(200).json({ clients });
});

app.get("/api/clients/untrusted", authenticateToken, async (req, res) => {
    const clients = await db.all("SELECT name, uuid, online, EXISTS(SELECT * FROM trust WHERE a = ? AND b = id) as trusted FROM users WHERE NOT EXISTS(SELECT * FROM trust WHERE a = ? AND b = id) AND NOT id = ?", req.user.id, req.user.id, req.user.id);
    res.status(200).json({ clients });
});

app.get("/api/clients/untrusted/online", authenticateToken, async (req, res) => {
    const clients = await db.all("SELECT name, uuid, online, EXISTS(SELECT * FROM trust WHERE a = ? AND b = id) as trusted FROM users WHERE NOT EXISTS(SELECT * FROM trust WHERE a = ? AND b = id) AND online = 1 AND NOT id = ?", req.user.id, req.user.id, req.user.id);
    res.status(200).json({ clients });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});

// const server = createServer({
//     cert: readFileSync('./certs/server.cert'),
//     key: readFileSync('./certs/server.key')
// });

const server = createServer();

const wss = new WebSocketServer({ server });
const uuidToClient = new Map(); //one uuid many clients
const clientToUser = new Map(); //one client one user

const pendingConnections = new Map();

// if the server is not started no one can be online
db.instance.exec("UPDATE users SET online = FALSE");

const cleanPendingConnection = (c) => {
    return {
        id: c.id,
        host: {
            user: c.host.user,
            token: c.host.token
        },
        client: {
            user: c.client.user,
            token: c.client.token
        }
    }
}

wss.on('connection', function connection(ws) {
    ws.on('error', console.error);

    ws.on('message', function (message) {
        try {
            const event = JSON.parse(message.toString());
            this.emit(event.type, event.payload);
        } catch (err) {
            console.log('not an event', err);
        }
    })
        .on('authenticate', (data) => {
            jwt.verify(data.token, process.env.JWT_KEY, async (err, _user) => {
                // now user is authenticated
                const user = await db.get("SELECT id, uuid, name, online FROM users WHERE uuid = ?", _user.uuid);
                // set user online
                db.instance.run("UPDATE users SET online = TRUE WHERE uuid = ?", user.uuid);

                uuidToClient.set(user.uuid, [...(uuidToClient.get(user.uuid) || []), ws]);
                clientToUser.set(ws, user);

                // send information to client about all connections that should happen automatically now
                const eligibleConnections = await db.all("SELECT name, uuid FROM users WHERE EXISTS(SELECT * FROM trust WHERE (a = ? AND b = id) OR (a = id AND b = ?)) AND online = 1 AND NOT id = ?", user.id, user.id, user.id);
                for (let connection of eligibleConnections) {
                    // get host code from ws
                    // send host code to client
                    const connectionID = uuidv4();
                    const pendingConnection = {
                        id: connectionID,
                        host: {
                            ws,
                            token: "",
                            user: {
                                name: user.name,
                                uuid: user.uuid
                            }
                        },
                        client: {
                            ws: uuidToClient.get(connection.uuid)[0],
                            token: "",
                            user: {
                                name: connection.name,
                                uuid: connection.uuid
                            }
                        }
                    };
                    pendingConnections.set(connectionID, pendingConnection);

                    pendingConnection.host.ws.send(JSON.stringify({ type: "request_host_token", payload: cleanPendingConnection(pendingConnection) }));
                }
            });
        })
        .on("host_token", (data) => {
            const pendingConnection = pendingConnections.get(data.connection);
            pendingConnection.host.token = data.token;

            pendingConnections.set(data.connection, pendingConnection);

            pendingConnection.client.ws.send(JSON.stringify({ type: "request_client_token", payload: cleanPendingConnection(pendingConnection) }));
        })
        .on("client_token", (data) => {
            const pendingConnection = pendingConnections.get(data.connection);
            pendingConnection.client.token = data.token;

            pendingConnections.set(data.connection, pendingConnection);

            pendingConnection.client.ws.send(JSON.stringify({ type: "request_finish_connection", payload: cleanPendingConnection(pendingConnection) }));
            pendingConnection.host.ws.send(JSON.stringify({ type: "request_finish_connection", payload: cleanPendingConnection(pendingConnection) }));
        })
        .on("finish_connection", (data) => {
            pendingConnections.delete(data.connection);
        });

    ws.on('close', () => {
        const user = clientToUser.get(ws);
        clientToUser.delete(ws);
        uuidToClient.set(user.uuid, (uuidToClient.get(user.uuid) || []).filter(w => w !== ws));

        if (uuidToClient.get(user.uuid).length === 0) {
            // set user offline
            db.instance.run("UPDATE users SET online = FALSE WHERE uuid = ?", user.uuid);
        }
    });
});

server.listen(7071, () => {
    console.log("WSS Server started at Port 7071");
});