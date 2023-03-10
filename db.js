import sqlite3 from 'sqlite3';

export class db {
  static instance = new sqlite3.Database('./data/database.sqlite');

  static get = (sql, ...params) => new Promise((resolve) => {
    db.instance.get(sql, ...params, (err, rows) => {
      if (err) {
        console.log(err);
        return reject(err);
      }
      else return resolve(rows);
    });
  });

  static all = (sql, ...params) => new Promise((resolve, reject) => {
    db.instance.all(sql, ...params, (err, rows) => {
      if (err) {
        console.log(err);
        return reject(err);
      }
      else return resolve(rows);
    });
  });

  static init = () => {
    db.instance.exec(`
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, uuid VARCHAR(255), name VARCHAR(255), password VARCHAR(255), online BOOLEAN DEFAULT FALSE);
    CREATE TABLE IF NOT EXISTS trust (a INTEGER, b INTEGER, PRIMARY KEY (a, b), FOREIGN KEY(a) REFERENCES users(id), FOREIGN KEY(b) REFERENCES users(id));
    `);
  };

  static drop = () => {
    db.instance.exec("DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS trust;");
  };
}