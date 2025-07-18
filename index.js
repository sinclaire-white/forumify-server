const express = require("express");
const cors = require("cors");
require("dotenv").config();
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb"); // Import ObjectId

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zxppowi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db("forumDB");
    const userCollection = db.collection("users");
    const postCollection = db.collection("posts");
    const commentsCollection = db.collection("comments"); // NEW: Comments Collection

    // Root route
    app.get("/", (req, res) => {
      res.send("Server is running!");
    });

    // Save or update user (register or Google login)
    app.post("/users", async (req, res) => {
      const user = req.body;
      const existingUser = await userCollection.findOne({ email: user.email });

      if (existingUser) {
        return res.send({ message: "User already exists" });
      }

      // Assign admin role only if email matches
      user.role = user.email === "white@walter.com" ? "admin" : "user";
      user.badge = "bronze";

      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // JWT creation route (verify Firebase token)
    app.post("/jwt", async (req, res) => {
      const { token } = req.body;
      console.log("Incoming Firebase Token:", token?.slice(0, 30), "...");

      try {
        const decodedUser = await admin.auth().verifyIdToken(token);
        console.log(" Token verified for:", decodedUser.email);

        const jwtToken = jwt.sign(
          { email: decodedUser.email, uid: decodedUser.uid },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.send({ token: jwtToken });
      } catch (error) {
        console.error("❌ Firebase token verification failed:", error.message);
        res.status(401).send({ error: "Unauthorized: Invalid Firebase token" });
      }
    });

    // JWT verification middleware
    const verifyJWT = (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.status(401).send("Unauthorized: No token");

      const token = authHeader.split(" ")[1];
      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send("Forbidden: Invalid token");
        req.user = decoded;
        next();
      });
    };

    // Admin role verification middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.user.email;
      const user = await userCollection.findOne({ email });
      if (!user || user.role !== "admin") {
        return res.status(403).send({ error: "Forbidden: Admins only" });
      }
      next();
    };

    // Public route to check if a user exists by email (no JWT required)
    app.get("/users/check-email", async (req, res) => {
      const email = req.query.email;
      if (!email) {
        return res
          .status(400)
          .send({ message: "Email query parameter is required." });
      }
      try {
        const user = await userCollection.findOne({ email });
        if (user) {
          res.send({
            exists: true,
            user: {
              _id: user._id,
              email: user.email,
              name: user.name,
              photo: user.photo,
              role: user.role,
              badge: user.badge,
            },
          });
        } else {
          res.send({ exists: false });
        }
      } catch (error) {
        console.error("Error checking user existence:", error);
        res
          .status(500)
          .send({ message: "Internal server error during email check." });
      }
    });

    // Admin-only route to get all users
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const users = await userCollection.find().toArray();
      res.send(users);
    });

    // Admin-only route to make a user admin
    app.patch("/users/make-admin", verifyJWT, verifyAdmin, async (req, res) => {
      const { email } = req.body;

      if (email === "white@walter.com") {
        return res.status(400).send({ error: "Cannot change main admin role" });
      }

      const result = await userCollection.updateOne(
        { email },
        { $set: { role: "admin" } }
      );

      if (result.matchedCount === 0) {
        return res.status(404).send({ error: "User not found" });
      }

      res.send({ message: `User ${email} promoted to admin` });
    });

    // check post count of a user (Protected: requires JWT)
    app.get("/posts/count", verifyJWT, async (req, res) => {
      const email = req.query.email;
      if (!email) return res.status(400).send({ message: "Missing email" });

      const count = await postCollection.countDocuments({ authorEmail: email });
      res.send({ count });
    });

    
    // New: Get total post count for pagination
    app.get("/posts-total-count", async (req, res) => {
      try {
        const count = await postCollection.estimatedDocumentCount();
        res.send({ count });
      } catch (error) {
        console.error("Error fetching total post count:", error);
        res.status(500).send({ message: "Error fetching total count." });
      }
    });

    // Public route to get all posts with optional search, tag filters, pagination, and sorting
    app.get("/posts", async (req, res) => {
      try {
        const { search, tag, sort, page = 1, limit = 5 } = req.query; // Added sort, page, limit
        const skip = (parseInt(page) - 1) * parseInt(limit);
        let query = {}; // MongoDB query object
        let sortOption = { createdAt: -1 }; // Default sort: newest to oldest

        // Build query based on parameters
        if (search) {
          query.$or = [
            { title: { $regex: search, $options: "i" } },
            { description: { $regex: search, $options: "i" } },
            { tag: { $regex: search, $options: "i" } }
          ];
        }
        if (tag) {
          query.tag = { $regex: `^${tag}$`, $options: "i" };
        }

        let pipeline = [];
        if (Object.keys(query).length > 0) {
            pipeline.push({ $match: query }); // Apply initial filters
        }

        if (sort === 'popularity') {
          // Aggregation for popularity sort
          pipeline.push(
            {
              $addFields: {
                voteDifference: { $subtract: ["$upVote", "$downVote"] }
              }
            },
            {
              $sort: { voteDifference: -1 } // Sort by popularity (descending)
            }
          );
        } else {
          // Default sort (newest to oldest) for other cases
          pipeline.push({ $sort: sortOption });
        }

        // Add pagination stages
        pipeline.push(
          { $skip: skip },
          { $limit: parseInt(limit) }
        );

        // Fetch posts
        const posts = await postCollection.aggregate(pipeline).toArray();

        // New: Get comment count for each post
       
        const postsWithCommentCounts = await Promise.all(posts.map(async (post) => {
          const commentCount = await commentsCollection.countDocuments({ postId: post._id.toString() });
          return { ...post, commentCount };
        }));

        res.send(postsWithCommentCounts);

      } catch (error) {
        console.error("Error fetching posts with filters:", error);
        res.status(500).send({ message: "Internal server error fetching posts." });
      }
    });

    // Route to get a single post by ID (public access)
    app.get("/posts/:id", async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid Post ID format." });
        }
        const query = { _id: new ObjectId(id) };
        const post = await postCollection.findOne(query);

        if (!post) {
          return res.status(404).send({ message: "Post not found." });
        }

        // Fetch comment count for the single post
        const commentCount = await commentsCollection.countDocuments({ postId: post._id.toString() });

        res.send({ ...post, commentCount }); // Include commentCount

      } catch (error) {
        console.error("Error fetching single post:", error);
        res.status(500).send({ message: "Internal server error fetching post." });
      }
    });

    // NEW: Add a comment to a post (Protected: requires JWT)
    app.post("/comments", verifyJWT, async (req, res) => {
      const { postId, commentText, authorEmail, authorName, authorPhoto, postTitle } = req.body; // Added postTitle
      if (!postId || !commentText || !authorEmail || !postTitle) {
        return res.status(400).send({ message: "Missing required comment fields." });
      }

      // Optional: Check if post exists
      const postExists = await postCollection.countDocuments({ _id: new ObjectId(postId) });
      if (postExists === 0) {
          return res.status(404).send({ message: "Post not found for commenting." });
      }

      const comment = {
        postId: postId, // Store as string for easier querying from frontend ID
        postTitle: postTitle, // Store post title for hint-2
        commentText,
        authorEmail,
        authorName,
        authorPhoto,
        createdAt: new Date(),
      };
      const result = await commentsCollection.insertOne(comment);
      res.send(result);
    });

    // NEW: Get comments for a specific post (Public access)
    app.get("/comments/:postId", async (req, res) => {
      try {
        const postId = req.params.postId;
        const comments = await commentsCollection.find({ postId: postId }).sort({ createdAt: 1 }).toArray(); // Sort oldest to newest
        res.send(comments);
      } catch (error) {
        console.error("Error fetching comments:", error);
        res.status(500).send({ message: "Error fetching comments." });
      }
    });

   

    // Add new post (Protected: requires JWT)
    app.post("/posts", verifyJWT, async (req, res) => {
      const post = req.body;
      post.upVote = 0;
      post.downVote = 0;
      post.createdAt = new Date();

      const result = await postCollection.insertOne(post);
      res.send(result);
    });

   


    app.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
    });
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}

run();