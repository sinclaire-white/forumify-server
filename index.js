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

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);


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
    const paymentsCollection = db.collection("payments"); // --- NEW: Payments Collection ---

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
        // Ensure 'membership' field exists, defaulting to false
        if (typeof existingUser.membership === 'undefined') {
          updateFields.membership = false;
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

      // Assign role, badge, and default membership for NEW users
      user.role = user.email === "white@walter.com" ? "admin" : "user";
      user.badge = "bronze"; // Default to bronze upon registration
      user.membership = false; // --- NEW: Default membership to false ---

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


    // Admin-only route to get all reported comments
    app.get("/reports", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const reports = await reportsCollection.find().sort({ reportedAt: -1 }).toArray();
        res.send(reports);
      } catch (error) {
        console.error("Error fetching reported comments:", error);
        res.status(500).send({ message: "Internal server error fetching reported comments." });
      }
    });

    // Admin-only route to delete a reported comment/activity
    app.delete("/reports/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const reportId = req.params.id;

      if (!ObjectId.isValid(reportId)) {
        return res.status(400).send({ message: "Invalid Report ID format." });
      }

      try {
        const report = await reportsCollection.findOne({ _id: new ObjectId(reportId) });
        if (!report) {
          return res.status(404).send({ message: "Report not found." });
        }

        if (report.commentId) {
          const commentDeleteResult = await commentsCollection.deleteOne({ _id: new ObjectId(report.commentId) });
          if (commentDeleteResult.deletedCount > 0) {
            console.log(`Associated comment ${report.commentId} deleted.`);
          } else {
            console.log(`Associated comment ${report.commentId} not found or already deleted.`);
          }
        }

        const result = await reportsCollection.deleteOne({ _id: new ObjectId(reportId) });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: "Report not found or could not be deleted." });
        }

        res.send({ message: "Report and associated comment (if existed) deleted successfully." });
      } catch (error) {
        console.error("Error deleting reported comment:", error);
        res.status(500).send({ message: "Internal server error deleting reported comment." });
      }
    });

    // Admin-only route to dismiss/approve a report (without deleting comment)
    app.patch("/reports/:id/dismiss", verifyJWT, verifyAdmin, async (req, res) => {
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
          return res.status(400).send({ message: "Report already dismissed or no changes made." });
        }
        res.send({ message: "Report dismissed successfully." });
      } catch (error) {
        console.error("Error dismissing report:", error);
        res.status(500).send({ message: "Internal server error dismissing report." });
      }
    })


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
              role: user.role || "user",
              badge: user.badge || "bronze",
              membership: typeof user.membership !== 'undefined' ? user.membership : false, // Ensure membership is sent
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

        const sanitizedUsers = users.map(user => {
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
        res.status(500).send({ message: "Internal server error fetching users." });
      }
    });

    // Admin-only route to make a user admin (updated to use ID from params)
    app.patch("/users/:id/make-admin", verifyJWT, verifyAdmin, async (req, res) => {
      const userId = req.params.id;

      if (!ObjectId.isValid(userId)) {
        return res.status(400).send({ message: "Invalid User ID format." });
      }

      try {
        const user = await userCollection.findOne({ _id: new ObjectId(userId) });
        if (!user) {
          return res.status(404).send({ message: "User not found." });
        }

        if (user.email === "white@walter.com") {
          return res.status(400).send({ error: "Cannot change main admin role." });
        }
        if (user.role === "admin") {
          return res.status(400).send({ message: "User is already an admin." });
        }

        const result = await userCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { role: "admin" } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ error: "User not found or role not changed." });
        }

        res.send({ message: `User ${user.name || user.email} promoted to admin.`, modifiedCount: result.modifiedCount });
      } catch (error) {
        console.error("Error making user admin:", error);
        res.status(500).send({ message: "Internal server error making user admin." });
      }
    });

    // for UserProfile: Update User Badge (now primarily for internal use/admin)
    app.patch("/users/update-badge", verifyJWT, async (req, res) => {
      const { email, badge } = req.body;
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
        const { search, tag, sort, page = 1, limit = 5 } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);
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
            {
              $sort: { voteDifference: -1 },
            }
          );
        } else {
          pipeline.push({ $sort: sortOption });
        }

        pipeline.push({ $skip: skip }, { $limit: parseInt(limit) });

        const posts = await postCollection.aggregate(pipeline).toArray();

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

    // NEW: Add a comment to a post (Protected: requires JWT)
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

    // Get comments for a specific post (Public access)
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

    // ENDPOINT: Submit a comment report ===
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

      if (reporterEmail !== req.user.email) {
        return res
          .status(403)
          .send({
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

    // Delete a post (Protected: requires JWT, only author can delete)
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
          return res
            .status(403)
            .send({
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

    // Update post votes (Protected: requires JWT)
    app.patch("/posts/vote/:id", verifyJWT, async (req, res) => {
      try {
        const postId = req.params.id;
        const { type } = req.body;

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
          { $inc: { [updateField]: 1 } }
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

    // stripe payment - Using Checkout Sessions (remains mostly the same)
    app.post("/create-checkout-session", async (req, res) => {
      try {
        const { email } = req.body;

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          mode: "payment",
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: "Forumify Gold Membership", // More descriptive name
                  description: "Unlock unlimited posts and features!"
                },
                unit_amount: 1000, // $10.00 membership
              },
              quantity: 1,
            },
          ],
          customer_email: email,
          // IMPORTANT: Pass session ID and client email as query params to success_url
          // This allows the frontend to retrieve session details for verification/recording
          success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}&email=${email}`,
          cancel_url: `${process.env.CLIENT_URL}/membership`, // Redirect to membership page if cancelled
        });

        res.send({ url: session.url });
      } catch (err) {
        console.error("Error creating checkout session:", err);
        res.status(500).send({ error: err.message });
      }
    });

    // --- MODIFIED: Update user membership and record payment ---
    // This endpoint will be called by the frontend after Stripe Checkout success redirect
    app.patch("/users/membership", verifyJWT, async (req, res) => {
      const { email, transactionId, amount, currency } = req.body; // Expecting more details

      // Security check: Ensure the requested email matches the authenticated user's email
      if (req.user.email !== email) {
        return res.status(403).send({ message: "Forbidden: Email mismatch." });
      }

      if (!email || !transactionId || !amount || !currency) {
        return res.status(400).send({ message: "Missing required payment details for membership upgrade." });
      }

      try {
        // 1. Record the payment in the new paymentsCollection
        const paymentRecord = {
          email: email,
          transactionId: transactionId,
          amount: amount, // Store the amount as received (e.g., 10 for $10)
          currency: currency,
          paymentType: "membership_upgrade",
          paidAt: new Date(),
        };
        await paymentsCollection.insertOne(paymentRecord);

        // 2. Update the user's membership and badge
        const updateResult = await userCollection.updateOne(
          { email },
          { $set: { membership: true, badge: "gold" } }
        );

        if (updateResult.modifiedCount > 0) {
          res.send({ success: true, message: "Membership upgraded and payment recorded." });
        } else {
          res.status(400).send({ success: false, message: "User not found or membership already gold." });
        }
      } catch (error) {
        console.error("Error upgrading membership and recording payment:", error);
        res.status(500).send({ success: false, message: "Failed to upgrade membership or record payment." });
      }
    });

    // --- NEW: Endpoint to get a user's payment history (for dashboard) ---
    app.get("/payments/history", verifyJWT, async (req, res) => {
      const email = req.query.email;

      // Security check: Only the authenticated user can view their own payment history
      if (!email || req.user.email !== email) {
        return res.status(403).send({ message: "Forbidden: Not authorized to view this payment history." });
      }

      try {
        const payments = await paymentsCollection.find({ email: email }).sort({ paidAt: -1 }).toArray();
        res.send(payments);
      } catch (error) {
        console.error("Error fetching payment history:", error);
        res.status(500).send({ message: "Failed to fetch payment history." });
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