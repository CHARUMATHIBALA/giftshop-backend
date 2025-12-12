require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const mongoose = require("mongoose");

// -------------------- MONGODB CONNECTION -------------------- //
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.log("DB Error:", err));

// -------------------- USER SCHEMA --------------------------- //
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model("User", UserSchema);

// -------------------- GIFT SCHEMA --------------------------- //
const GiftSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    price: { type: Number, required: true },
    category: { type: String },
    image: { type: String },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});

const Gift = mongoose.model("Gift", GiftSchema);

// -------------------- EXPRESS SETUP -------------------------- //
const app = express();
app.use(cors());
app.use(express.json());

// -------------------- JWT VERIFY MIDDLEWARE ------------------- //
const verifyToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).send("No token provided");

    const token = authHeader.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : authHeader;

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).send("Invalid token");
        req.userId = decoded.userId;
        next();
    });
};

// -------------------- REGISTER ------------------------------- //
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });

    } catch (err) {
        console.log(err);
        res.status(500).send("Server error");
    }
});

// -------------------- LOGIN ---------------------------------- //
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(400).send("Invalid credentials");

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(400).send("Invalid credentials");

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });

    } catch (err) {
        console.log(err);
        res.status(500).send("Server error");
    }
});

// -------------------- ADD GIFT ------------------------------- //
app.post("/api/gifts", verifyToken, async (req, res) => {
    try {
        const { title, description, price, category, image } = req.body;

        const gift = new Gift({
            title,
            description,
            price,
            category,
            image,
            createdBy: req.userId
        });

        await gift.save();
        res.status(201).json(gift);

    } catch (err) {
        console.log(err);
        res.status(500).send("Server error");
    }
});

// -------------------- GET GIFTS (Only user gifts) ------------- //
app.get("/api/gifts", verifyToken, async (req, res) => {
    try {
        const gifts = await Gift.find({ createdBy: req.userId });
        res.json(gifts);

    } catch (err) {
        console.log(err);
        res.status(500).send("Server error");
    }
});

// -------------------- DELETE GIFT ----------------------------- //
app.delete("/api/gifts/:id", verifyToken, async (req, res) => {
    try {
        const deleted = await Gift.findOneAndDelete({
            _id: req.params.id,
            createdBy: req.userId
        });

        if (!deleted) return res.status(404).send("Gift not found");

        res.send("Gift deleted");

    } catch (err) {
        console.log(err);
        res.status(500).send("Server error");
    }
});

// -------------------- UPDATE GIFT ----------------------------- //
app.put("/api/gifts/:id", verifyToken, async (req, res) => {
    try {
        const { title, description, price, category, image } = req.body;

        const updated = await Gift.findOneAndUpdate(
            { _id: req.params.id, createdBy: req.userId },
            { title, description, price, category, image },
            { new: true }
        );

        if (!updated) return res.status(404).send("Gift not found");

        res.json(updated);

    } catch (err) {
        console.log(err);
        res.status(500).send("Server error");
    }
});

// -------------------- SERVER START ----------------------------- //
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Gift Shop backend running on port ${PORT}`));
