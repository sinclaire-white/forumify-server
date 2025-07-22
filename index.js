const express = require("express");
const cors = require("cors");
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
    // Root route
    app.get("/", (req, res) => {
      res.send("Server is running!");
    });

    // Save or update user (register or Google login)

    app.post("/users", async (req, res) => {
      const user = req.body;
      const existingUser = await userCollection.findOne({ email: user.email });

      if (existingUser) {
        // Ensure existing users also have role and badge if missing (for retrofitting)
        let needsUpdate = false;
        let updateFields = {};

        if (!existingUser.badge) {
          //  If badge is missing
          updateFields.badge = "bronze";
          needsUpdate = true;
        }
        if (!existingUser.role) {
          //  If role is missing
          updateFields.role =
            user.email === "white@walter.com" ? "admin" : "user";
          needsUpdate = true;
        }

        if (needsUpdate) {
          await userCollection.updateOne(
            { email: user.email },
            { $set: updateFields }
          );
          // Fetch updated user to send back
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

      // Assign role and badge for NEW users
      user.role = user.email === "white@walter.com" ? "admin" : "user";
      user.badge = "bronze"; // Default to bronze upon registration

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
  const { name } = req.body;
  if (!name || name.trim() === "") {
    return res.status(400).send({ message: "Tag name cannot be empty." });
  }

  try {
    const existingTag = await tagsCollection.findOne({ name: { $regex: new RegExp(`^${name}$`, 'i') } });
    if (existingTag) {
      return res.status(409).send({ message: `Tag '${name}' already exists.` });
    }

    const result = await tagsCollection.insertOne({ name: name.trim().toLowerCase() });
    res.status(201).send({ message: "Tag added successfully", tagId: result.insertedId });
  } catch (error) {
    console.error("Error adding tag:", error);
    res.status(500).send({ message: "Internal server error adding tag." });
  }
});

// Admin-only route to get all tags (useful for frontend dropdowns)
app.get("/tags", async (req, res) => {
  try {
    const tags = await tagsCollection.find({}).toArray();
    res.send(tags);
  } catch (error) {
    console.error("Error fetching tags:", error);
    res.status(500).send({ message: "Internal server error fetching tags." });
  }
});

// Admin-only route to make an announcement
app.post("/announcements", verifyJWT, verifyAdmin, async (req, res) => {
  const { authorImage, authorName, title, description } = req.body;

  if (!authorImage || !authorName || !title || !description) {
    return res.status(400).send({ message: "Missing required announcement fields." });
  }

  try {
    const newAnnouncement = {
      authorImage,
      authorName,
      title,
      description,
      createdAt: new Date(),
    };
    const result = await announcementsCollection.insertOne(newAnnouncement);
    res.status(201).send({ message: "Announcement created successfully", announcementId: result.insertedId });
  } catch (error) {
    console.error("Error creating announcement:", error);
    res.status(500).send({ message: "Internal server error creating announcement." });
  }
});

// Public route to get all announcements (for homepage display)
app.get("/announcements", async (req, res) => {
    try {
        const announcements = await announcementsCollection.find().sort({ createdAt: -1 }).toArray();
        res.send(announcements);
    } catch (error) {
        console.error("Error fetching announcements:", error);
        res.status(500).send({ message: "Internal server error fetching announcements." });
    }
});

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
              role: user.role || "user", // Ensure role is always sent, default to 'user'
              badge: user.badge || "bronze", // Ensure badge is always sent, default to 'bronze'
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

    // for UserProfile: Update User Badge
    app.patch("/users/update-badge", verifyJWT, async (req, res) => {
      const { email, badge } = req.body;
      // Only the user themselves or an admin can update their badge
      if (req.user.email !== email && req.user.role !== "admin") {
        return res
          .status(403)
          .send({
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

    // check post count of a user (Protected: requires JWT)
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
        const { search, tag, sort, page = 1, limit = 5 } = req.query; // Added sort, page, limit
        const skip = (parseInt(page) - 1) * parseInt(limit);
        let query = {}; // MongoDB query object
        let sortOption = { createdAt: -1 }; // Default sort: newest to oldest

        // Build query based on parameters
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
          pipeline.push({ $match: query }); // Apply initial filters
        }

        if (sort === "popularity") {
          // Aggregation for popularity sort
          pipeline.push(
            {
              $addFields: {
                voteDifference: { $subtract: ["$upVote", "$downVote"] },
              },
            },
            {
              $sort: { voteDifference: -1 }, // Sort by popularity (descending)
            }
          );
        } else {
          // Default sort (newest to oldest) for other cases
          pipeline.push({ $sort: sortOption });
        }

        // Add pagination stages
        pipeline.push({ $skip: skip }, { $limit: parseInt(limit) });

        // Fetch posts
        const posts = await postCollection.aggregate(pipeline).toArray();

        //  Get comment count for each post

        const postsWithCommentCounts = await Promise.all(
          posts.map(async (post) => {
            const commentCount = await commentsCollection.countDocuments({
              postId: post._id.toString(),
            });
            return { ...post, commentCount };
          })
        );

        res.send(postsWithCommentCounts);
      } catch (error) {
        console.error("Error fetching posts with filters:", error);
        res
          .status(500)
          .send({ message: "Internal server error fetching posts." });
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
        const commentCount = await commentsCollection.countDocuments({
          postId: post._id.toString(),
        });

        res.send({ ...post, commentCount }); // Include commentCount
      } catch (error) {
        console.error("Error fetching single post:", error);
        res
          .status(500)
          .send({ message: "Internal server error fetching post." });
      }
    });

    // NEW: Add a comment to a post (Protected: requires JWT)
    app.post("/comments", verifyJWT, async (req, res) => {
      const {
        postId,
        commentText,
        authorEmail,
        authorName,
        authorPhoto,
        postTitle,
      } = req.body; // Added postTitle
      if (!postId || !commentText || !authorEmail || !postTitle) {
        return res
          .status(400)
          .send({ message: "Missing required comment fields." });
      }

      // Optional: Check if post exists
      const postExists = await postCollection.countDocuments({
        _id: new ObjectId(postId),
      });
      if (postExists === 0) {
        return res
          .status(404)
          .send({ message: "Post not found for commenting." });
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

    // Get comments for a specific post (Public access)
    app.get("/comments/:postId", async (req, res) => {
      try {
        const postId = req.params.postId;
        const comments = await commentsCollection
          .find({ postId: postId })
          .sort({ createdAt: 1 })
          .toArray(); // Sort oldest to newest
        res.send(comments);
      } catch (error) {
        console.error("Error fetching comments:", error);
        res.status(500).send({ message: "Error fetching comments." });
      }
    });

    //  ENDPOINT: Submit a comment report ===
    app.post("/reports", verifyJWT, async (req, res) => {
      const { commentId, feedback, reporterEmail } = req.body;

      if (!commentId || !feedback || !reporterEmail) {
        return res
          .status(400)
          .send({
            message:
              "Missing required report fields (commentId, feedback, reporterEmail).",
          });
      }

      // Security check: Ensure the reporter's email matches the authenticated user's email
      if (reporterEmail !== req.user.email) {
        return res
          .status(403)
          .send({
            message:
              "Forbidden: Reporter email mismatch with authenticated user.",
          });
      }

      try {
        // Optional: Check if the comment actually exists (good practice)
        const comment = await commentsCollection.findOne({
          _id: new ObjectId(commentId),
        });
        if (!comment) {
          return res.status(404).send({ message: "Comment not found." });
        }

        // Check if this specific user has already reported this comment to prevent duplicates
        const existingReport = await reportsCollection.findOne({
          commentId: commentId,
          reporterEmail: reporterEmail,
        });

        if (existingReport) {
          return res
            .status(409)
            .send({ message: "You have already reported this comment." });
        }

        // Create the report document to be stored in the 'reports' collection
        const report = {
          commentId: commentId,
          postId: comment.postId, // Link report to the original post ID
          commentText: comment.commentText, // Store comment text for admin context
          commenterEmail: comment.authorEmail, // Store commenter's email
          feedback, // The selected feedback reason
          reporterEmail, // The email of the user who reported
          status: "pending", // Initial status for admin review
          reportedAt: new Date(), // Timestamp of the report
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

    // Add new post (Protected: requires JWT)
    app.post("/posts", verifyJWT, async (req, res) => {
      const post = req.body;
      post.upVote = 0;
      post.downVote = 0;
      post.createdAt = new Date();

      const result = await postCollection.insertOne(post);
      res.send(result);
    });

    //for UserProfile: Get a user's recent posts

    app.get("/my-posts", verifyJWT, async (req, res) => {
      try {
        const email = req.query.email;
        const limit = parseInt(req.query.limit) || 0; // Optional limit (e.g., for "recent 3 posts")

        // Security check: Ensure the requested email matches the authenticated user's email
        if (!email || email !== req.user.email) {
          return res
            .status(403)
            .send({ message: "Forbidden: Unauthorized access to posts." });
        }

        let pipeline = [
          { $match: { authorEmail: email } }, // Filter by the user's email
          {
            $addFields: {
              // Convert the post's ObjectId _id to a string to match comment.postId
              postIdString: { $toString: "$_id" },
            },
          },
          {
            $lookup: {
              // Join with comments collection to count comments
              from: "comments",
              localField: "postIdString", // Use the new string field for lookup
              foreignField: "postId", // Comment's postId (string of ObjectId)
              as: "comments",
            },
          },
          {
            $addFields: {
              // Add commentCount field
              commentCount: { $size: "$comments" }, // Count of comments for each post
            },
          },
          { $sort: { createdAt: -1 } }, // Sort newest to oldest for "Recent Posts"
          { $project: { comments: 0, postIdString: 0 } }, // Exclude the comments array and the temporary postIdString
        ];

        if (limit > 0) {
          pipeline.push({ $limit: limit }); // Apply limit if specified (e.g., for 3 recent posts)
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

    // Delete a post (Protected: requires JWT, only author can delete)
    app.delete("/posts/:id", verifyJWT, async (req, res) => {
      try {
        const postId = req.params.id;
        const userEmail = req.user.email; // Email of the authenticated user

        if (!ObjectId.isValid(postId)) {
          return res.status(400).send({ message: "Invalid Post ID format." });
        }

        const post = await postCollection.findOne({
          _id: new ObjectId(postId),
        });
        if (!post) {
          return res.status(404).send({ message: "Post not found." });
        }

        // Authorization check: Ensure only the author can delete their post
        if (post.authorEmail !== userEmail) {
          return res
            .status(403)
            .send({
              message: "Forbidden: You are not the author of this post.",
            });
        }

        // Delete the post
        const result = await postCollection.deleteOne({
          _id: new ObjectId(postId),
        });

        if (result.deletedCount === 0) {
          return res
            .status(404)
            .send({ message: "Post not found or could not be deleted." });
        }

        // IMPORTANT: Also delete all associated comments for the deleted post
        // Assuming comments `postId` field stores the string ID of the post
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

    // Update post votes (Protected: requires JWT)
    app.patch("/posts/vote/:id", verifyJWT, async (req, res) => {
      try {
        const postId = req.params.id;
        const { type } = req.body; // 'upvote' or 'downvote'

        if (!ObjectId.isValid(postId)) {
          return res.status(400).send({ message: "Invalid Post ID format." });
        }
        if (type !== "upvote" && type !== "downvote") {
          return res.status(400).send({
            message: "Invalid vote type. Must be 'upvote' or 'downvote'.",
          });
        }

        const updateField = type === "upvote" ? "upVote" : "downVote";
        const result = await postCollection.updateOne(
          { _id: new ObjectId(postId) },
          { $inc: { [updateField]: 1 } } // Increment by 1
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Post not found." });
        }
        res.send({
          message: `Post ${type}d successfully.`,
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error(`Error ${type}ing post:`, error);
        res
          .status(500)
          .send({ message: "Internal server error during voting." });
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
