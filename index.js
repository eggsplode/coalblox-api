const pool = require("./db");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const corsOptions = {
    origin: "https://eggsplode.github.io",
    credentials: true
};

app.use(cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Password hashing
function hashPassword(password) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString("hex");

        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(
                salt + ":" + derivedKey.toString("hex")
            );
        });
    });
}

function verifyPassword(password, storedPassword) {
    return new Promise((resolve, reject) => {
        if (!storedPassword || !storedPassword.includes(":")) {
            resolve(false);
            return;
        }

        const parts = storedPassword.split(":");
        const salt = parts[0];
        const storedKey = Buffer.from(parts[1], "hex");

        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
            if (err) {
                reject(err);
                return;
            }

            if (storedKey.length !== derivedKey.length) {
                resolve(false);
                return;
            }

            resolve(
                crypto.timingSafeEqual(
                    storedKey,
                    derivedKey
                )
            );
        });
    });
}

function createSessionToken() {
    return crypto.randomBytes(32).toString("hex");
}

function hashSessionToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function getSessionToken(req) {
    const cookies = req.headers.cookie;

    if (!cookies) {
        return null;
    }

    const sessionCookie = cookies
        .split(";")
        .map(cookie => cookie.trim())
        .find(cookie => cookie.startsWith("session="));

    if (!sessionCookie) {
        return null;
    }

    return decodeURIComponent(
        sessionCookie.substring("session=".length)
    );
}

async function createSession(userId) {
    const token = createSessionToken();
    const tokenHash = hashSessionToken(token);

    const expiresAt = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
    );

    await pool.query(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        [userId, tokenHash, expiresAt]
    );

    return token;
}

async function findUser(username) {
    const result = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
    );

    return result.rows[0];
}

// Login page test
app.get("/login/v1", (req, res) => {
    res.json({
        success: true,
        message: "Login endpoint exists. Use POST."
    });
});

// Login
app.post("/login/v1", async (req, res) => {
    const { username, password } = req.body || {};

    // Do NOT log the password.
    console.log("LOGIN:", username);

    try {
        if (!username || !password) {
            return res.json({
                success: false,
                message: "Username and password are required"
            });
        }

        const user = await findUser(username);

        if (!user) {
            return res.json({
                success: false,
                message: "Invalid username or password"
            });
        }

        let validPassword = false;

        // New hashed passwords
        if (user.password && user.password.includes(":")) {
            validPassword = await verifyPassword(
                password,
                user.password
            );
        } else {
            // Support old plaintext accounts once,
            // then immediately convert them to a hash.
            validPassword = user.password === password;

            if (validPassword) {
                const passwordHash = await hashPassword(password);

                await pool.query(
                    "UPDATE users SET password = $1 WHERE id = $2",
                    [passwordHash, user.id]
                );
            }
        }

        if (!validPassword) {
            return res.json({
                success: false,
                message: "Invalid username or password"
            });
        }

        const sessionToken = await createSession(user.id);

        res.cookie("session", sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/"
        });

        console.log("Logged in:", user.username);

        return res.json({
            success: true,
            redirect: "https://eggsplode.github.io/games"
        });

    } catch (err) {
        console.error(err);

        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// Session check
app.get("/session", async (req, res) => {
    try {
        const token = getSessionToken(req);

        if (!token) {
            return res.json({
                success: false,
                loggedIn: false
            });
        }

        const tokenHash = hashSessionToken(token);

        const result = await pool.query(
            "SELECT users.id, users.username FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW()",
            [tokenHash]
        );

        if (result.rows.length === 0) {
            return res.json({
                success: false,
                loggedIn: false
            });
        }

        return res.json({
            success: true,
            loggedIn: true,
            user: result.rows[0]
        });

    } catch (err) {
        console.error(err);

        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// Logout
app.post("/logout", async (req, res) => {
    try {
        const token = getSessionToken(req);

        if (token) {
            const tokenHash = hashSessionToken(token);

            await pool.query(
                "DELETE FROM sessions WHERE token_hash = $1",
                [tokenHash]
            );
        }

        res.clearCookie("session", {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            path: "/"
        });

        return res.json({
            success: true,
            message: "Logged out"
        });

    } catch (err) {
        console.error(err);

        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// dbtest
app.get("/dbtest", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");

        res.json({
            success: true,
            time: result.rows[0]
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            success: false,
            error: err.message
        });
    }
});

// Signup
app.post("/signup/v1", async (req, res) => {
    const { username, password } = req.body || {};

    // Do NOT log the password.
    console.log("Signup:", username);

    try {
        if (!username || !password) {
            return res.json({
                success: false,
                message: "Username and password are required"
            });
        }

        const existingUser = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );

        if (existingUser.rows.length > 0) {
            return res.json({
                success: false,
                message: "Username already exists"
            });
        }

        const passwordHash = await hashPassword(password);

        const result = await pool.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username",
            [username, passwordHash]
        );

        const user = result.rows[0];

        // Automatically log the new user in.
        const sessionToken = await createSession(user.id);

        res.cookie("session", sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/"
        });

        res.json({
            success: true,
            userId: user.id,
            username: user.username,
            message: "Account created!"
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// Captcha
app.post("/captcha/validate/signup", (req, res) => {
    res.json({
        success: true,
        message: "Captcha passed"
    });
});

app.post("/captcha/validate/login", (req, res) => {
    res.json({
        success: true,
        message: "Captcha passed"
    });
});

app.get("/xboxlive/get-roblox-userInfo", async (req, res) => {
    try {
        const userId = req.query.userId;

        if (!userId) {
            return res.status(400).json({
                error: "Missing userId"
            });
        }

        const result = await pool.query(
            "SELECT id, username FROM users WHERE id = $1",
            [userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: "User not found"
            });
        }

        const user = result.rows[0];

        res.json({
            userId: user.id,
            username: user.username,
            displayName: user.username
        });
    } catch (err) {
        console.error(err);

        res.status(500).json({
            error: "Failed to get user"
        });
    }
});

app.get("/xboxlive/get-inventory", (req, res) => {
    res.json([]);
});

app.post("/xboxlive/consume-all", (req, res) => {
    res.json({ success: true });
});

app.get("/xbox/translate", (req, res) => {
    res.json({ userId: null });
});

app.post("/xboxlive/connect", (req, res) => {
    res.json({ success: true });
});


app.get("/xbox/get-party-info", (req, res) => {
    res.json({});
});

app.post("/xboxlive/link-existing-user", (req, res) => {
    res.json({ success: true });
});

app.post("/xboxlive/disconnect", (req, res) => {
    res.json({ success: true });
});

app.post("/xboxlive/set-roblox-username-password", (req, res) => {
    res.json({ success: true });
});

app.get("/xboxlive/has-linked-account", (req, res) => {
    res.json({ linked: false });
});

app.get("/xboxlive/has-set-username-password", (req, res) => {
    res.json({ set: false });
});

// Username checker
app.get("/UserCheck/checkifinvalidusernameforsignup", (req, res) => {
    const username = req.query.username;

    res.json({
        success: true,
        isValid: true,
        IsValid: true,
        username: username || "",
        message: "Username is available"
    });
});

// Debug routes
app.get("/routes", (req, res) => {
    res.json({
        routes: [
            "GET /",
            "POST /device/initialize",
            "GET /login/v1",
            "POST /login/v1",
            "POST /signup/v1",
            "POST /logout",
            "GET /session",
            "POST /captcha/validate/login",
            "POST /captcha/validate/signup",
            "GET /UserCheck/checkifinvalidusernameforsignup",
            "GET /xboxlive/get-roblox-userInfo",
            "GET /xboxlive/get-inventory",
            "POST /xboxlive/consume-all",
            "GET /xbox/translate",
            "POST /xboxlive/connect",
            "GET /xbox/get-party-info",
            "POST /xboxlive/link-existing-user",
            "POST /xboxlive/disconnect",
            "POST /xboxlive/set-roblox-username-password",
            "GET /xboxlive/has-linked-account",
            "GET /xboxlive/has-set-username-password"
        ]
    });
});

// API homepage
app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "Eggsplode! API is running",
        version: "1.0",
        time: new Date()
    });
});

// Device initialize
app.post("/device/initialize", (req, res) => {
    res.json({
        success: true,
        message: "Device initialized"
    });
});

app.get("/Game/Join.ashx", (req, res) => {
    const userId = Number(req.query.userId || req.query.UserId || 0);
    const username = req.query.username || req.query.UserName || "Player";
    const placeId = Number(req.query.placeId || req.query.PlaceId || 0);
    const machineAddress = process.env.GAME_SERVER_ADDRESS || "127.0.0.1";
    const serverPort = Number(process.env.GAME_SERVER_PORT || 53640);
    const gameId = req.query.gameId || crypto.randomUUID();
    const sessionId = crypto.randomUUID();

    res.type("text/plain").send(JSON.stringify({
        ClientPort: 0,
        MachineAddress: machineAddress,
        ServerPort: serverPort,
        PingUrl: "",
        PingInterval: 120,
        UserName: username,
        SeleniumTestMode: false,
        UserId: userId,
        SuperSafeChat: true,
        CharacterAppearance: "https://coalblox-api-yh3x.onrender.com/Asset/CharacterFetch.ashx?userId=" + userId + "&placeId=" + placeId,
        ClientTicket: crypto.randomBytes(32).toString("base64"),
        GameId: gameId,
        PlaceId: placeId,
        MeasurementUrl: "",
        WaitingForCharacterGuid: crypto.randomUUID(),
        BaseUrl: "https://coalblox-api-yh3x.onrender.com/",
        ChatStyle: "Classic",
        VendorId: 0,
        ScreenShotInfo: "",
        VideoInfo: "",
        CreatorId: 0,
        CreatorTypeEnum: "User",
        MembershipType: "None",
        AccountAge: 0,
        CookieStoreFirstTimePlayKey: "rbx_evt_ftp",
        CookieStoreFiveMinutePlayKey: "rbx_evt_fmp",
        CookieStoreEnabled: true,
        IsRobloxPlace: false,
        GenerateTeleportJoin: false,
        IsUnknownOrUnder13: true,
        SessionId: sessionId,
        DataCenterId: 0,
        UniverseId: 0,
        BrowserTrackerId: 0,
        UsePortraitMode: false,
        FollowUserId: 0
    }));
});

app.get("/game/join.ashx", (req, res) => {
    const query = new URLSearchParams(req.query).toString();
    res.redirect("/Game/Join.ashx" + (query ? "?" + query : ""));
});

app.get("/Game/PlaceLauncher.ashx", (req, res) => {
    const placeId = req.query.placeId || req.query.PlaceId || 0;
    const username = req.query.username || req.query.UserName || "Player";
    const userId = req.query.userId || req.query.UserId || 0;

    res.json({
        status: 2,
        jobId: crypto.randomUUID(),
        joinScriptUrl:
            "https://coalblox-api-yh3x.onrender.com/Game/Join.ashx?" +
            new URLSearchParams({
                placeId: String(placeId),
                username: String(username),
                userId: String(userId)
            }).toString()
    });
});

app.get("/game/placelauncher.ashx", (req, res) => {
    const placeId = req.query.placeId || req.query.PlaceId || 0;
    const username = req.query.username || req.query.UserName || "Player";
    const userId = req.query.userId || req.query.UserId || 0;

    res.json({
        status: 2,
        jobId: crypto.randomUUID(),
        joinScriptUrl:
            "https://coalblox-api-yh3x.onrender.com/Game/Join.ashx?" +
            new URLSearchParams({
                placeId: String(placeId),
                username: String(username),
                userId: String(userId)
            }).toString()
    });
});

app.get("/Game/JoinRate.ashx", (req, res) => {
    res.status(200).send("");
});

app.get("/game/joinrate.ashx", (req, res) => {
    res.status(200).send("");
});

app.get("/Asset/CharacterFetch.ashx", (req, res) => {
    res.type("text/plain").send("");
});

app.get("/asset/characterfetch.ashx", (req, res) => {
    res.type("text/plain").send("");
});

app.get("/client-status", (req, res) => {
    res.json({
        success: true,
        status: "ok"
    });
});

// 404 (MUST STAY LAST)
app.use((req, res) => {
    console.log("404:", req.method, req.url);

    res.status(404).json({
        success: false,
        message: "Endpoint not found",
        method: req.method,
        path: req.path
    });
});

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
    console.log("Server running on port " + port);
});