# auth-middleware-express

#### npm i auth-middleware-express

```js
const authMiddleware from 'auth-middleware-express';
const express = require('express');

const { SECRET_1, SECRET_2 } = require('../keys.config');
const db from '../database';

const findUser = async (id: string) => {
    const user = await db.models.User.findOne({ _id: id });
    return { id: user._id.toString() };
}

const auth = authMiddleware(findUser, SECRET_1, SECRET_2).auth;

const app = express();

// use auth as middleware
app.use(auth);
```
