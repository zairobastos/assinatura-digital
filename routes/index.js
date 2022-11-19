var express = require("express");
var router = express.Router();
let crypto = require("crypto");

/* GET home page. */
router.get("/", function (req, res, next) {
	res.render("index", { title: "Express" });
});

router.get("/generate-key-pair", (req, res) => {
	const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: {
			type: "spki",
			format: "der",
		},
		privateKeyEncoding: {
			type: "pkcs8",
			format: "der",
		},
	});

	res.send({
		publicKey: publicKey.toString("base64"),
		privateKey: privateKey.toString("base64"),
	});
});

router.get("/generate-key-pair-alice", (req, res) => {
	const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: {
			type: "spki",
			format: "der",
		},
		privateKeyEncoding: {
			type: "pkcs8",
			format: "der",
		},
	});

	res.send({
		publicKey: publicKey.toString("base64"),
		privateKey: privateKey.toString("base64"),
	});
});

router.post("/sign", (req, res) => {
	let data = req.body.data;
	let privateKey = req.body.privateKey;

	let hash = crypto.getHashes();
	privateKey = crypto.createPrivateKey({
		key: Buffer.from(privateKey, "base64"),
		type: "pkcs8",
		format: "der",
	});

	const sign = crypto.createSign("SHA256");
	sign.update(data);
	sign.end();
	let hashPwd = crypto.createHash("sha1").update(data).digest("hex");
	const signature = sign.sign(privateKey).toString("base64");
	res.send({
		data,
		hash_mensagem: hashPwd,
		signature,
	});
});

router.post("/verify", (req, res) => {
	let { data, publicKey, signature } = req.body;

	publicKey = crypto.createPublicKey({
		key: Buffer.from(publicKey, "base64"),
		type: "spki",
		format: "der",
	});
	const verify = crypto.createVerify("SHA256");
	verify.update(data);
	verify.end();

	let result = verify.verify(publicKey, Buffer.from(signature, "base64"));
	res.send({
		verify: result,
	});
});

module.exports = router;
