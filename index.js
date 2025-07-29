const express = require("express");
const cors = require("cors");
const Stripe = require("stripe");
require("dotenv").config();
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decodedKey);

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

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
    const commentsCollection = db.collection("comments");
    const reportsCollection = db.collection("reports");
    const tagsCollection = db.collection("tags");
    const announcementsCollection = db.collection("announcements");
    const searchesCollection = db.collection("searches");


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

    // Post limit check middleware
    const checkPostLimit = async (req, res, next) => {
      const user = await userCollection.findOne({ email: req.user.email });
      const postCount = await postCollection.countDocuments({
        authorEmail: user.email,
      });
      if (user.badge === "bronze" && postCount >= 5) {
        return res
          .status(403)
          .send({ message: "Post limit reached. Upgrade to gold." });
      }
      next();
    };

    // Root route
    app.get("/", (req, res) => {
      res.send("Server is running!");
    });

    // Save or update user (register or Google login)
    app.post("/users", async (req, res) => {
      const user = req.body;
      const existingUser = await userCollection.findOne({ email: user.email });

      if (existingUser) {
        let needsUpdate = false;
        let updateFields = {};

        if (!existingUser.badge) {
          updateFields.badge = "bronze";
          needsUpdate = true;
        }
        if (!existingUser.role) {
          updateFields.role =
            user.email === "white@walter.com" ? "admin" : "user";
          needsUpdate = true;
        }

        if (needsUpdate) {
          await userCollection.updateOne(
            { email: user.email },
            { $set: updateFields }
          );
          const updatedExistingUser = await userCollection.findOne({
            email: user.email,
          });
          return res.send({
            message: "User already exists, updated info",
            user: updatedExistingUser,
          });
        }

        return res.send({ message: "User already exists", user: existingUser });
      }

      user.role = user.email === "white@walter.com" ? "admin" : "user";
      user.badge = "bronze";
      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // JWT creation route (verify Firebase token)
    app.post("/jwt", async (req, res) => {
      const { token } = req.body;
      try {
        const decodedUser = await admin.auth().verifyIdToken(token);
        console.log("Token verified for:", decodedUser.email);

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

    // Admin-only route to get site statistics
    app.get("/admin-stats", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const totalUsers = await userCollection.countDocuments();
        const totalPosts = await postCollection.countDocuments();
        const totalComments = await commentsCollection.countDocuments();

        res.send({ totalUsers, totalPosts, totalComments });
      } catch (error) {
        console.error("Error fetching admin stats:", error);
        res
          .status(500)
          .send({ message: "Internal server error fetching admin stats." });
      }
    });

    // Admin-only route to add a new tag
    app.post("/tags", verifyJWT, verifyAdmin, async (req, res) => {
      const { names } = req.body;
      if (!Array.isArray(names) || names.length === 0) {
        return res
          .status(400)
          .send({ message: "Tag names array is required." });
      }

      try {
        const results = [];
        for (const name of names) {
          if (!name || name.trim() === "") continue;
          const trimmedName = name.trim().toLowerCase();
          const existingTag = await tagsCollection.findOne({
            name: { $regex: new RegExp(`^${trimmedName}$`, "i") },
          });
          if (existingTag) {
            results.push({
              name: trimmedName,
              message: `Tag '${trimmedName}' already exists.`,
            });
            continue;
          }
          const result = await tagsCollection.insertOne({ name: trimmedName });
          results.push({ name: trimmedName, tagId: result.insertedId });
        }
        res.status(201).send({ message: "Tags processed", results });
      } catch (error) {
        console.error("Error adding tags:", error);
        res.status(500).send({ message: "Internal server error adding tags." });
      }
    });

    // Admin-only route to get all tags
    app.get("/tags", async (req, res) => {
      try {
        const tags = await tagsCollection.find({}).toArray();
        res.send(tags);
      } catch (error) {
        console.error("Error fetching tags:", error);
        res
          .status(500)
          .send({ message: "Internal server error fetching tags." });
      }
    });

    // Admin-only route to make an announcement
    app.post("/announcements", verifyJWT, verifyAdmin, async (req, res) => {
      const { title, description, authorImage } = req.body;

      if (!title || !description) {
        return res
          .status(400)
          .send({ message: "Missing required fields: title and description." });
      }

      try {
        const user = await userCollection.findOne({ email: req.user.email });
        const authorName = user?.name || "Site Admin";
        const newAnnouncement = {
          authorName,
          title,
          description,
          authorImage: authorImage || null,
          createdAt: new Date(),
        };
        const result = await announcementsCollection.insertOne(newAnnouncement);
        res.status(201).send({
          message: "Announcement created successfully",
          announcementId: result.insertedId,
        });
      } catch (error) {
        console.error("Error creating announcement:", error);
        res
          .status(500)
          .send({ message: "Internal server error creating announcement." });
      }
    });

    // Public route to get all announcements
    app.get("/announcements", async (req, res) => {
      try {
        const announcements = await announcementsCollection
          .find()
          .sort({ createdAt: -1 })
          .toArray();
        res.send(announcements);
      } catch (error) {
        console.error("Error fetching announcements:", error);
        res
          .status(500)
          .send({ message: "Internal server error fetching announcements." });
      }
    });

    // Admin-only route to get all reported comments
    app.get("/reports", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const reports = await reportsCollection
          .find()
          .sort({ reportedAt: -1 })
          .toArray();
        res.send(reports);
      } catch (error) {
        console.error("Error fetching reported comments:", error);
        res.status(500).send({
          message: "Internal server error fetching reported comments.",
        });
      }
    });

    // Admin-only route to delete a reported comment
    app.delete("/reports/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const reportId = req.params.id;

      if (!ObjectId.isValid(reportId)) {
        return res.status(400).send({ message: "Invalid Report ID format." });
      }

      try {
        const report = await reportsCollection.findOne({
          _id: new ObjectId(reportId),
        });
        if (!report) {
          return res.status(404).send({ message: "Report not found." });
        }

        if (report.commentId) {
          const commentDeleteResult = await commentsCollection.deleteOne({
            _id: new ObjectId(report.commentId),
          });
          if (commentDeleteResult.deletedCount > 0) {
            console.log(`Associated comment ${report.commentId} deleted.`);
          } else {
            console.log(
              `Associated comment ${report.commentId} not found or already deleted.`
            );
          }
        }

        const result = await reportsCollection.deleteOne({
          _id: new ObjectId(reportId),
        });

        if (result.deletedCount === 0) {
          return res
            .status(404)
            .send({ message: "Report not found or could not be deleted." });
        }

        res.send({
          message:
            "Report and associated comment (if existed) deleted successfully.",
        });
      } catch (error) {
        console.error("Error deleting reported comment:", error);
        res.status(500).send({
          message: "Internal server error deleting reported comment.",
        });
      }
    });

    // Admin-only route to dismiss a report
    app.patch(
      "/reports/:id/dismiss",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const reportId = req.params.id;

        if (!ObjectId.isValid(reportId)) {
          return res.status(400).send({ message: "Invalid Report ID format." });
        }

        try {
          const result = await reportsCollection.updateOne(
            { _id: new ObjectId(reportId) },
            { $set: { status: "dismissed", dismissedAt: new Date() } }
          );

          if (result.matchedCount === 0) {
            return res.status(404).send({ message: "Report not found." });
          }
          if (result.modifiedCount === 0) {
            return res.status(400).send({
              message: "Report already dismissed or no changes made.",
            });
          }
          res.send({ message: "Report dismissed successfully." });
        } catch (error) {
          console.error("Error dismissing report:", error);
          res
            .status(500)
            .send({ message: "Internal server error dismissing report." });
        }
      }
    );

    // Public route to check if a user exists by email
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
              role: user.role || "user",
              badge: user.badge || "bronze",
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

    // Admin-only route to get all users with search and pagination
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const { search, page = 1, limit = 10 } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);
        let query = {};

        if (search) {
          query.name = { $regex: search, $options: "i" };
        }

        const totalUsers = await userCollection.countDocuments(query);
        const users = await userCollection
          .find(query)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        const sanitizedUsers = users.map((user) => {
          const { password, ...rest } = user;
          return rest;
        });

        res.send({
          users: sanitizedUsers,
          totalUsers,
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalUsers / parseInt(limit)),
        });
      } catch (error) {
        console.error("Error fetching users:", error);
        res
          .status(500)
          .send({ message: "Internal server error fetching users." });
      }
    });

    // Route to fetch a single user by email
    app.get("/users/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      try {
        const query = { email: email };
        const user = await userCollection.findOne(query);
        if (user) {
          res.send(user);
        } else {
          res.status(404).send({ message: "User not found." });
        }
      } catch (error) {
        console.error("Error fetching user by email:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    // Admin-only route to make a user admin
    app.patch(
      "/users/:id/make-admin",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const userId = req.params.id;

        if (!ObjectId.isValid(userId)) {
          return res.status(400).send({ message: "Invalid User ID format." });
        }

        try {
          const user = await userCollection.findOne({
            _id: new ObjectId(userId),
          });
          if (!user) {
            return res.status(404).send({ message: "User not found." });
          }

          if (user.email === "white@walter.com") {
            return res
              .status(400)
              .send({ error: "Cannot change main admin role." });
          }
          if (user.role === "admin") {
            return res
              .status(400)
              .send({ message: "User is already an admin." });
          }

          const result = await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { role: "admin" } }
          );

          if (result.matchedCount === 0) {
            return res
              .status(404)
              .send({ error: "User not found or role not changed." });
          }

          res.send({
            message: `User ${user.name || user.email} promoted to admin.`,
            modifiedCount: result.modifiedCount,
          });
        } catch (error) {
          console.error("Error making user admin:", error);
          res
            .status(500)
            .send({ message: "Internal server error making user admin." });
        }
      }
    );

    // Update User Badge
    app.patch("/users/update-badge", verifyJWT, async (req, res) => {
      const { email, badge } = req.body;
      if (req.user.email !== email && req.user.role !== "admin") {
        return res.status(403).send({
          message: "Forbidden: Not authorized to update this user's badge.",
        });
      }
      if (!email || !badge) {
        return res
          .status(400)
          .send({ message: "Email and badge are required." });
      }
      if (!["bronze", "gold"].includes(badge)) {
        return res.status(400).send({ message: "Invalid badge type." });
      }

      try {
        const result = await userCollection.updateOne(
          { email: email },
          { $set: { badge: badge } }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "User not found." });
        }
        res.send({ message: `User ${email}'s badge updated to ${badge}.` });
      } catch (error) {
        console.error("Error updating user badge:", error);
        res
          .status(500)
          .send({ message: "Internal server error updating badge." });
      }
    });

    // Check post count of a user
    app.get("/posts/count", verifyJWT, async (req, res) => {
      const email = req.query.email;
      if (!email || email !== req.user.email) {
        return res
          .status(403)
          .send({ message: "Forbidden: Unauthorized access to post count." });
      }

      const count = await postCollection.countDocuments({ authorEmail: email });
      res.send({ count });
    });

    // Get total post count for pagination
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
        const { search, tag, sort, page = 1, limit = 5 } = req.query;

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        let query = {};
        let sortOption = { createdAt: -1 };

        if (search) {
          query.$or = [
            { title: { $regex: search, $options: "i" } },
            { description: { $regex: search, $options: "i" } },
            { tag: { $regex: search, $options: "i" } },
          ];
        }
        if (tag) {
          query.tag = { $regex: `^${tag}$`, $options: "i" };
        }

        let pipeline = [];
        if (Object.keys(query).length > 0) {
          pipeline.push({ $match: query });
        }

        if (sort === "popularity") {
          pipeline.push(
            {
              $addFields: {
                voteDifference: { $subtract: ["$upVote", "$downVote"] },
              },
            },
            { $sort: { voteDifference: -1 } }
          );
        } else {
          pipeline.push({ $sort: sortOption });
        }

        pipeline.push({ $skip: skip }, { $limit: limitNum });

        const posts = await postCollection.aggregate(pipeline).toArray();

        const postsWithCounts = await Promise.all(
          posts.map(async (post) => {
            const commentCount = await commentsCollection.countDocuments({
              postId: post._id.toString(),
            });
            return { ...post, commentCount };
          })
        );

        const totalCount = await postCollection.countDocuments(query);

        res.send({ posts: postsWithCounts, totalCount });
      } catch (error) {
        console.error("Server error fetching posts:", error);
        res.status(500).send({ message: "Server error" });
      }
    });

    

    // Route to get a single post by ID
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

        const commentCount = await commentsCollection.countDocuments({
          postId: post._id.toString(),
        });

        res.send({ ...post, commentCount });
      } catch (error) {
        console.error("Error fetching single post:", error);
        res
          .status(500)
          .send({ message: "Internal server error fetching post." });
      }
    });

    // Add a comment to a post
    app.post("/comments", verifyJWT, async (req, res) => {
      const {
        postId,
        commentText,
        authorEmail,
        authorName,
        authorPhoto,
        postTitle,
      } = req.body;
      if (!postId || !commentText || !authorEmail || !postTitle) {
        return res
          .status(400)
          .send({ message: "Missing required comment fields." });
      }

      const postExists = await postCollection.countDocuments({
        _id: new ObjectId(postId),
      });
      if (postExists === 0) {
        return res
          .status(404)
          .send({ message: "Post not found for commenting." });
      }

      const comment = {
        postId: postId,
        postTitle: postTitle,
        commentText,
        authorEmail,
        authorName,
        authorPhoto,
        createdAt: new Date(),
      };
      const result = await commentsCollection.insertOne(comment);
      res.send(result);
    });

    // Get comments for a specific post
    app.get("/comments/:postId", async (req, res) => {
      try {
        const postId = req.params.postId;
        const comments = await commentsCollection
          .find({ postId: postId })
          .sort({ createdAt: 1 })
          .toArray();
        res.send(comments);
      } catch (error) {
        console.error("Error fetching comments:", error);
        res.status(500).send({ message: "Error fetching comments." });
      }
    });

    // Submit a comment report
    app.post("/reports", verifyJWT, async (req, res) => {
      const { commentId, feedback, reporterEmail } = req.body;

      if (!commentId || !feedback || !reporterEmail) {
        return res.status(400).send({
          message:
            "Missing required report fields (commentId, feedback, reporterEmail).",
        });
      }

      if (reporterEmail !== req.user.email) {
        return res.status(403).send({
          message:
            "Forbidden: Reporter email mismatch with authenticated user.",
        });
      }

      try {
        const comment = await commentsCollection.findOne({
          _id: new ObjectId(commentId),
        });
        if (!comment) {
          return res.status(404).send({ message: "Comment not found." });
        }

        const existingReport = await reportsCollection.findOne({
          commentId: commentId,
          reporterEmail: reporterEmail,
        });

        if (existingReport) {
          return res
            .status(409)
            .send({ message: "You have already reported this comment." });
        }

        const report = {
          commentId: commentId,
          postId: comment.postId,
          commentText: comment.commentText,
          commenterEmail: comment.authorEmail,
          feedback,
          reporterEmail,
          status: "pending",
          reportedAt: new Date(),
        };
        const result = await reportsCollection.insertOne(report);
        res.send(result);
      } catch (error) {
        console.error("Error submitting report:", error);
        res
          .status(500)
          .send({ message: "Internal server error submitting report." });
      }
    });

    // Add new post
    app.post("/posts", verifyJWT, checkPostLimit, async (req, res) => {
      const post = req.body;
      post.upVote = 0;
      post.downVote = 0;
      post.createdAt = new Date();
      post.visibility = "public";
      post.votedBy = [];
      const result = await postCollection.insertOne(post);
      res.send(result);
    });

    // Get a user's recent posts
    app.get("/my-posts", verifyJWT, async (req, res) => {
      try {
        const email = req.query.email;
        const limit = parseInt(req.query.limit) || 0;

        if (!email || email !== req.user.email) {
          return res
            .status(403)
            .send({ message: "Forbidden: Unauthorized access to posts." });
        }

        let pipeline = [
          { $match: { authorEmail: email } },
          {
            $addFields: {
              postIdString: { $toString: "$_id" },
            },
          },
          {
            $lookup: {
              from: "comments",
              localField: "postIdString",
              foreignField: "postId",
              as: "comments",
            },
          },
          {
            $addFields: {
              commentCount: { $size: "$comments" },
            },
          },
          { $sort: { createdAt: -1 } },
          { $project: { comments: 0, postIdString: 0 } },
        ];

        if (limit > 0) {
          pipeline.push({ $limit: limit });
        }

        const myPosts = await postCollection.aggregate(pipeline).toArray();
        res.send(myPosts);
      } catch (error) {
        console.error("Error fetching user's posts for profile:", error);
        res
          .status(500)
          .send({ message: "Internal server error fetching your posts." });
      }
    });

    // Post visibility
    app.patch("/posts/:id/visibility", verifyJWT, async (req, res) => {
      const { visibility } = req.body;
      await postCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { visibility } }
      );
      res.send({ success: true });
    });

    // Delete a post
    app.delete("/posts/:id", verifyJWT, async (req, res) => {
      try {
        const postId = req.params.id;
        const userEmail = req.user.email;

        if (!ObjectId.isValid(postId)) {
          return res.status(400).send({ message: "Invalid Post ID format." });
        }

        const post = await postCollection.findOne({
          _id: new ObjectId(postId),
        });
        if (!post) {
          return res.status(404).send({ message: "Post not found." });
        }

        if (post.authorEmail !== userEmail) {
          return res.status(403).send({
            message: "Forbidden: You are not the author of this post.",
          });
        }

        const result = await postCollection.deleteOne({
          _id: new ObjectId(postId),
        });

        if (result.deletedCount === 0) {
          return res
            .status(404)
            .send({ message: "Post not found or could not be deleted." });
        }

        await commentsCollection.deleteMany({ postId: postId });

        res.send({
          message: "Post and its comments deleted successfully.",
          deletedCount: result.deletedCount,
        });
      } catch (error) {
        console.error("Error deleting post:", error);
        res
          .status(500)
          .send({ message: "Internal server error during post deletion." });
      }
    });
   // Record a search term
app.post("/record-search", verifyJWT, async (req, res) => {
  try {
    const { searchTerm } = req.body;
    const userEmail = req.user.email;
    if (!searchTerm || typeof searchTerm !== "string") {
      return res.status(400).send({ message: "Invalid search term" });
    }
    const trimmedTerm = searchTerm.trim().toLowerCase();
    await searchesCollection.updateOne(
      { searchTerm: trimmedTerm, userEmail },
      { $set: { lastSearched: new Date() } },
      { upsert: true }
    );
    res.send({ message: "Search recorded" });
  } catch (error) {
    console.error("Error recording search:", error);
    res.status(500).send({ message: "Server error" });
  }
});

// Get top 3 recent popular searches
app.get("/popular-searches", async (req, res) => {
  try {
    const { limit = 3, sort = "lastSearched" } = req.query;
    const parsedLimit = parseInt(limit) || 3;
    const pipeline = [
      {
        $match: { searchTerm: { $ne: null, $type: "string" } }
      },
      {
        $group: {
          _id: "$searchTerm",
          count: { $sum: 1 },
          lastSearched: { $max: "$lastSearched" }
        }
      },
      { $sort: { lastSearched: -1 } },
      { $limit: parsedLimit }
    ];
    const results = await searchesCollection.aggregate(pipeline).toArray();
    res.send(results);
  } catch (error) {
    console.error("Error fetching popular searches:", error);
    res.status(500).send({ message: "Server error" });
  }
});
    // Update post votes
    app.patch("/posts/vote/:id", verifyJWT, async (req, res) => {
      try {
        const postId = req.params.id;
        const { type } = req.body;
        const userEmail = req.user.email;

        if (!ObjectId.isValid(postId)) {
          return res.status(400).send({ message: "Invalid Post ID format." });
        }
        if (type !== "upvote" && type !== "downvote") {
          return res.status(400).send({
            message: "Invalid vote type. Must be 'upvote' or 'downvote'.",
          });
        }

        const post = await postCollection.findOne({
          _id: new ObjectId(postId),
        });

        if (!post) {
          return res.status(404).send({ message: "Post not found." });
        }

        if (!post.votedBy) {
          post.votedBy = [];
        }

        const existingVoteIndex = post.votedBy.findIndex(
          (vote) => vote.userEmail === userEmail
        );

        let update = {};
        let message = "";

        if (existingVoteIndex === -1) {
          update = {
            $inc: { [type === "upvote" ? "upVote" : "downVote"]: 1 },
            $push: { votedBy: { userEmail: userEmail, voteType: type } },
          };
          message = `Post ${type}d successfully.`;
        } else {
          const existingVoteType = post.votedBy[existingVoteIndex].voteType;

          if (existingVoteType === type) {
            update = {
              $inc: { [type === "upvote" ? "upVote" : "downVote"]: -1 },
              $pull: { votedBy: { userEmail: userEmail } },
            };
            message = `Your ${type} has been removed.`;
          } else {
            update = {
              $inc: {
                [existingVoteType === "upvote" ? "upVote" : "downVote"]: -1,
                [type === "upvote" ? "upVote" : "downVote"]: 1,
              },
              $set: { [`votedBy.${existingVoteIndex}.voteType`]: type },
            };
            message = `Your vote has been changed to ${type}.`;
          }
        }

        const result = await postCollection.updateOne(
          { _id: new ObjectId(postId) },
          update
        );

        if (result.matchedCount === 0) {
          return res
            .status(404)
            .send({ message: "Post not found or already removed." });
        }

        res.send({
          success: true,
          message: message,
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error("Error processing vote:", error);
        res
          .status(500)
          .send({ message: "Internal server error during voting." });
      }
    });

    // Update membership
    app.patch("/users/membership", verifyJWT, async (req, res) => {
      const { email, transactionId, amount, currency } = req.body;

      if (req.user.email !== email) {
        return res.status(403).send({
          message:
            "Forbidden: You are not authorized to update this user's membership.",
        });
      }

      try {
        const result = await userCollection.updateOne(
          { email: email },
          {
            $set: {
              membership: true,
              badge: "gold",
              transactionId,
              amount,
              currency,
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "User not found." });
        }

        if (result.modifiedCount === 0) {
          return res
            .status(200)
            .send({ message: "Membership already up to date.", success: true });
        }

        res.send({ success: true, message: "Membership updated to Gold!" });
      } catch (error) {
        console.error("Error updating user membership:", error);
        res
          .status(500)
          .send({ message: "Internal server error updating membership." });
      }
    });

    // Create Stripe checkout session
    app.post("/create-checkout-session", verifyJWT, async (req, res) => {
      const { email } = req.body;

      if (!email || email !== req.user.email) {
        return res
          .status(400)
          .send({
            error: "Valid email is required and must match authenticated user",
          });
      }

      try {
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          mode: "payment",
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: "Forumify Membership",
                  description: "Unlock unlimited posts and a Gold badge!",
                },
                unit_amount: 1000,
              },
              quantity: 1,
            },
          ],
          customer_email: email,
          success_url: `${
            process.env.CLIENT_URL
          }/payment-success?session_id={CHECKOUT_SESSION_ID}&email=${encodeURIComponent(
            email
          )}`,
          cancel_url: `${process.env.CLIENT_URL}/payment-cancel`,
        });
        res.send({ id: session.id, url: session.url });
      } catch (err) {
        console.error("Error creating Stripe checkout session:", err);
        res
          .status(500)
          .send({
            error: "Failed to create checkout session",
            details: err.message,
          });
      }
    });

    app.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
    });
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}

run();
