'use strict';
/** Tiny JSON-file user database with atomic writes. Swap for a real DB in production. */
const fs = require('node:fs');
const path = require('node:path');

class Store {
  constructor(dataDir) {
    this.file = path.join(dataDir, 'db.json');
    this.data = fs.existsSync(this.file)
      ? JSON.parse(fs.readFileSync(this.file, 'utf8'))
      : { users: {} };
  }

  save() {
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  getUser(id) {
    return this.data.users[id] || null;
  }

  findByEmail(email) {
    const e = String(email).toLowerCase();
    return Object.values(this.data.users).find((u) => u.email === e) || null;
  }

  find(predicate) {
    return Object.values(this.data.users).find(predicate) || null;
  }

  addUser(user) {
    this.data.users[user.id] = user;
    this.save();
    return user;
  }
}

module.exports = { Store };
