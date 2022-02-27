const fs = require("fs");
const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router("./db.json");
const middlewares = jsonServer.defaults();
const jwt = require("jsonwebtoken");
const { nanoid } = require("nanoid");

server.db = router.db;

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, "SECRET_KEY");
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, "SECRET_KEY", (err, decode) =>
    decode !== undefined ? decode : err
  );
}

// Check if the username exists and password match in database
function login({ username, email, phone, password }) {
  let dataLogin = { username, email, phone };
  Object.keys(dataLogin).forEach((v) => {
    if (!dataLogin[v]) delete dataLogin[v];
  });
  if (!password) return false;
  if (Object.keys(dataLogin).length === 0) return false;
  return router.db
    .get("users")
    .find({ ...dataLogin, password })
    .value();
}

// Check if the username exists
function isUsernameExist(username) {
  return !!router.db.get("users").find({ username }).value();
}

// Check if the phone exists
function isPhoneExist(phone) {
  return !!router.db.get("users").find({ phone }).value();
}

// Check if the email exists
function isEmailExist(email) {
  return !!router.db.get("users").find({ email }).value();
}

server.use(jsonServer.bodyParser);
server.use(middlewares);

// login
server.post("/api/v1/auth/login", (req, res) => {
  const user = login({
    username: req.body.username,
    email: req.body.email,
    phone: req.body.phone,
    password: req.body.password,
  });
  if (!user)
    return res.status(401).json({
      succes: false,
      message: "gagal login",
      access_token: null,
    });

  const token = createToken(user);
  res.status(200).json({
    success: true,
    message: "success login",
    access_token: `Bearer ${token}`,
  });
});

// register
server.post("/api/v1/auth/register", (req, res) => {
  try {
    if (!req.body.name) {
      throw new Error("gagal register: masukkan name");
    } else if (!req.body.username) {
      throw new Error("gagal register: masukkan username");
    } else if (req.body.username.length < 3) {
      throw new Error("gagal register: username minimal 3 karakter");
    } else if (!req.body.password) {
      throw new Error("gagal register: masukkan password");
    } else if (req.body.password.length < 8) {
      throw new Error("gagal register: password minimal 8 karakter");
    } else if (isUsernameExist(req.body.username)) {
      throw new Error("gagal register: username sudah terpakai");
    } else if (isPhoneExist(req.body.phone)) {
      throw new Error("gagal register: phone sudah terpakai");
    } else if (isEmailExist(req.body.email)) {
      throw new Error("gagal register: email sudah terpakai");
    }

    const newUser = {
      id: nanoid(7),
      name: req.body.name,
      username: req.body.username,
      password: req.body.password,
      phone: req.body?.phone || "",
      email: req.body?.email || "",
    };
    router.db.get("users").push(newUser).value();
    router.db.write();

    res.status(200).json({
      success: true,
      message: "success register",
    });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error.message,
    });
  }
});

// middleware checking user is authenticated
server.use(/^(?!\/api\/v1\/auth).*$/, async (req, res, next) => {
  // const tes2 = low(new FileSync(products));
  // tes2.write();
  // console.log(3333123, halo);
  console.log(3333123, "halo");

  try {
    const { authorization } = req.headers;
    const hasAuthorizationHeader = authorization?.split(" ")[0] === "Bearer";

    if (!hasAuthorizationHeader) {
      throw new Error("Authorization header tidak ditemukan");
    }

    const { password, ...data } = verifyToken(authorization.split(" ")[1]);

    const isTokenValid =
      data.name !== "JsonWebTokenError" && data.message !== "invalid signature";
    if (!isTokenValid) {
      throw new Error("Access token tidak valid");
    }

    req.userAuth = data;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error.message,
    });
  }
});

// middleware #
server.use(/^(?!\/api\/v1\/auth).*$/, async (req, res, next) => {
  if (req.method === "POST" && req.originalUrl.includes("tweets")) {
    req.body = { ...req.body, userId: req.userAuth.id };
  }

  if (req.method === "PATCH" && req.originalUrl.includes("tweets")) {
    const tes = req.originalUrl.split("/");
    const tweetId = tes.pop() || tes.pop();
    const data = router.db
      .get("tweets")
      .find({
        id: +tweetId,
        userId: req.userAuth.id,
      })
      .value();

    // tidak bisa merubah id dan user id
    const { id, userId, ...newData } = req.body;
    req.body = newData;

    // gagal merubah data
    if (!data)
      return res.status(405).json({
        success: false,
        message:
          "gagal update tweet: anda tidak memiliki hak untuk merubah tweet ini",
      });
  }

  if (req.method === "DELETE" && req.originalUrl.includes("tweets")) {
    const tes = req.originalUrl.split("/");
    const tweetId = tes.pop() || tes.pop();
    const data = router.db
      .get("tweets")
      .find({
        id: +tweetId,
        userId: req.userAuth.id,
      })
      .value();

    // gagal merubah data
    if (!data)
      return res.status(405).json({
        success: false,
        message:
          "gagal delete tweet: tweet tidak ada / anda tidak memiliki hak untuk menghapus tweet ini",
      });
  }

  next();
});

// filter resource only show if relation to user
router.render = (req, res) => {
  if (req.originalUrl.includes("tweets")) {
    const isArray = Array.isArray(res.locals.data);
    if (isArray) {
      const filterDataRelationToUser = res.locals.data.filter(
        (v) => v.userId === req.userAuth.id
      );
      return res.jsonp({
        success: true,
        message: "success",
        data: filterDataRelationToUser,
      });
    }

    const hasRelationToUser = res.locals.data.userId === req.userAuth.id;
    return res.jsonp({
      success: true,
      message: "success",
      data: hasRelationToUser ? res.locals.data : {},
    });
  }

  return res.jsonp({
    success: true,
    message: "success",
    data: res.locals.data,
  });
};

server.use("/api/v1", router);

server.listen(3000, () => {
  console.log("JSON Server is running");
});
