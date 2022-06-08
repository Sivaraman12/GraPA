const { generateKeyPair } = require("crypto");
const fs = require('fs');
const User = require("../models/User");
const bcrypt = require("bcryptjs");

//Register Route
async function grammarDecoder(password) {
  const alphabet = await User.Alphabet.find({});
  let currentIds = {};
  let previousIds = {};
  userPassword = "";
  alphabet.forEach((record) => {
    currentIds[record["current"]] = record["alphabet"];
    previousIds[record["previous"]] = record["alphabet"];
  });
  let letters = [];
  if (password.includes(alphabet[0]["currenttimestamp"])) {
    letters = password.split(alphabet[0]["currenttimestamp"]);
    letters.forEach((id) => {
      if (!currentIds[id]) return false;
      else userPassword += currentIds[id];
    });
  } else if (
    alphabet[0]["previoustimestamp"] &&
    password.includes(alphabet[0]["previoustimestamp"])
  ) {
    letters = password.split(alphabet[0]["previoustimestamp"]);
    letters.forEach((id) => {
      if (!previousIds[id]) return false;
      else userPassword += previousIds[id];
    });
  } else return false;
  return userPassword;
}

exports.register = async (req, res) => {
  let { username, email, password } = req.body;
  console.log(password);
  password = await grammarDecoder(password);
  if (!password) return res.status(500).json("Password verification failed !!");
  // Get the hashed password
  password = await bcrypt.hash(password, 12);
  generateKeyPair(
    "rsa",
    {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: "pkcs1",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs1",
        format: "pem",
      },
    },
    (err, publicKey, privateKey) => {
      if (err) console.log("Error!", err);
      // console.log({
      //   publicKey,
      //   privateKey,
      // });
      const pubkey = publicKey;
      try {
        User.User.create(
          {
            username,
            email,
            password,
            pubkey
          },
          function (err, user) {
            if (err) return res.status(404).json(err);
            else return res.status(200).json(user);
          }
        );
      } catch (error) {
        console.log(error);
      }
      fs.writeFile('E:/Siva Repository/GraPA/prikey.pem', privateKey, err => {
        if (err) {
          console.error(err);
        }
      });
    }
  );
};

//Register Route
exports.login = async (req, res) => {
  try {
    let { email, password } = req.body;
    password = await grammarDecoder(password);
    if (!password)
      return res.status(500).json("Password varification failed !!");
    const user = await User.User.findOne({ email: email });
    //password = await bcrypt.hash(password, 12);
    if (!user) return res.status(404).json("user not found");
    const prikey = fs.readFileSync("E:/Siva Repository/GraPA/prikey.pem", { encoding: "utf8" });
    const pubkey = user.pubkey;
    const verifiableData = "this need to be verified";
    const signature = require("crypto").sign(
      "sha256",
      Buffer.from(verifiableData),
      {
        key: prikey,
        padding: require("crypto").constants.RSA_PKCS1_PSS_PADDING,
      }
    );
    //console.log(signature.toString("base64"));

    const isVerified = require("crypto").verify(
      "sha256",
      Buffer.from(verifiableData),
      {
        key: pubkey,
        padding: require("crypto").constants.RSA_PKCS1_PSS_PADDING,
      },
      Buffer.from(signature.toString("base64"), "base64")
    );
    let isMatch = await bcrypt.compare(password, user.password);
    if (isMatch && isVerified) {
      return res.status(200).json(user);
    } else {
      return res.status(500).json("Wrong Password !!");
    }
  } catch (err) {
    return res.status(500).json(err);
  }
};

//Grammar verify
exports.grammar = async (req, res) => {
  try {
    let alphabet = await User.Alphabet.find({});
    if (!alphabet) return res.status(404).json("Grammar not found !!");
    let response = { timestamp: "", data: {} };
    response["timestamp"] = alphabet[0]["currenttimestamp"];
    alphabet.forEach((record) => {
      response["data"][record["alphabet"]] = record["current"];
    });
    return res.status(200).json(response);
  } catch (error) {
    console.log(error);
  }
};
