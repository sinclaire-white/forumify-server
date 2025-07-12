const express = require('express');
const cors = require('cors');
require("dotenv").config();
const admin = require("firebase-admin");
// const fs = require("fs");
const serviceAccount = require("./ServiceAccountKey.json");
const { MongoClient, ServerApiVersion } = require('mongodb');



admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());








// Mongo URI & client setup
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zxppowi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect();
    const db = client.db("forumDB");

    console.log("✅ Connected to MongoDB!");

    // Sample route
    app.get('/', (req, res) => {
      res.send('✅ Server is running!');
    });

    // Ping Mongo
    app.get('/ping', async (req, res) => {
      const result = await db.command({ ping: 1 });
      res.send({ message: '✅ Pinged MongoDB!', result });
    });

    // Start server
    
  } catch (err) {
    console.error('❌ Error connecting to MongoDB:', err.message);
  }
  app.listen(port, () => {
      console.log(`🚀 Server running on http://localhost:${port}`);
    });
}

run();
